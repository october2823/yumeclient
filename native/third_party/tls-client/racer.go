package tls_client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	quic "github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/http3"
	"github.com/bogdanfinn/tls-client/bandwidth"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
	"github.com/quic-go/qpack"
)

type protocolRacer struct {
	protocolCache   map[string]string
	protocolCacheMu sync.RWMutex
	// broken: addresses where HTTP/3 failed after connecting (guarded by
	// protocolCacheMu); races leave HTTP/3 out until the entry expires
	broken map[string]brokenHTTP3

	clientSessionCache  tls.ClientSessionCache
	insecureSkipVerify  bool
	serverNameOverwrite string
	transportOptions    *TransportOptions
	settings            map[http2.SettingID]uint32
	cachedTransports    map[string]http.RoundTripper
	cachedTransportsLck *sync.Mutex
	certificatePinner   CertificatePinner
	badPinHandlerFunc   BadPinHandlerFunc
	bandwidthTracker    bandwidth.BandwidthTracker

	// dropTransport forgets the transport cached for an address so the next
	// attempt builds one from a fresh handshake. It is the round tripper's own
	// eviction, handed over because a raced request returns from RoundTrip
	// before the branch that would otherwise do it.
	dropTransport func(addr string, stale http.RoundTripper)

	// discardConn closes the connection a lost HTTP/2 attempt dialed (stashed for
	// the transport by dialTLS).
	discardConn func(addr string)

	// uses counts the requests of HTTP/1.1 and HTTP/2 transports (http.RoundTripper
	// -> *usage) so a discarded one closes its connections after them.
	uses sync.Map
	// closed: the round tripper is closed, nothing gets cached (guarded by
	// cachedTransportsLck)
	closed bool

	// HTTP/3 specific settings
	http3Settings          map[uint64]uint64
	http3SettingsOrder     []uint64
	http3PriorityParam     uint32
	http3PseudoHeaderOrder []string
	http3SendGreaseFrames  bool
	http3Fingerprint       *profiles.HTTP3Fingerprint

	proxyURL string
}

func newProtocolRacer(
	clientSessionCache tls.ClientSessionCache,
	insecureSkipVerify bool,
	serverNameOverwrite string,
	transportOptions *TransportOptions,
	settings map[http2.SettingID]uint32,
	cachedTransports map[string]http.RoundTripper,
	cachedTransportsLck *sync.Mutex,
	dropTransport func(addr string, stale http.RoundTripper),
	certificatePinner CertificatePinner,
	badPinHandlerFunc BadPinHandlerFunc,
	bandwidthTracker bandwidth.BandwidthTracker,
	http3Settings map[uint64]uint64,
	http3SettingsOrder []uint64,
	http3PriorityParam uint32,
	http3PseudoHeaderOrder []string,
	http3SendGreaseFrames bool,
	proxyURL string,
) *protocolRacer {
	return &protocolRacer{
		protocolCache:          make(map[string]string),
		clientSessionCache:     clientSessionCache,
		insecureSkipVerify:     insecureSkipVerify,
		serverNameOverwrite:    serverNameOverwrite,
		transportOptions:       transportOptions,
		settings:               settings,
		cachedTransports:       cachedTransports,
		cachedTransportsLck:    cachedTransportsLck,
		dropTransport:          dropTransport,
		certificatePinner:      certificatePinner,
		badPinHandlerFunc:      badPinHandlerFunc,
		bandwidthTracker:       bandwidthTracker,
		http3Settings:          http3Settings,
		http3SettingsOrder:     http3SettingsOrder,
		http3PriorityParam:     http3PriorityParam,
		http3PseudoHeaderOrder: http3PseudoHeaderOrder,
		http3SendGreaseFrames:  http3SendGreaseFrames,
		proxyURL:               proxyURL,
	}
}

// race races HTTP/3 and HTTP/2 connections and sends the request over whichever
// connects first. Similar to Chrome's "Happy Eyeballs" approach.
func (pr *protocolRacer) race(req *http.Request, addr string, getTransportFunc func(*http.Request, string) error) (*http.Response, error) {
	if pr.isClosed() {
		return nil, errClosed
	}
	// Try cached protocol first if available
	resp, err, retry := pr.tryUseCachedProtocol(req, addr, getTransportFunc)
	if retry == nil {
		return resp, err
	}

	// No cached protocol or it failed - start racing
	resp, err = pr.startRace(retry, addr, getTransportFunc)
	var failed *HTTP3BrokenError
	if err == nil || !errors.As(err, &failed) {
		return resp, err
	}
	// HTTP/3 connected, then failed the request: like Chrome, HTTP/3 counts as
	// broken for this server and the request goes again over TCP when that is safe
	if again := retryRequest(retry, failed.Err); again != nil {
		return pr.startRace(again, addr, getTransportFunc)
	}
	return nil, err
}

// retryRequest: the request to send again after err, or nil when it must not be
// (cancelled or timed out, or not idempotent and maybe processed).
func retryRequest(req *http.Request, err error) *http.Request {
	notSent := errors.Is(err, http3.ErrTransportClosed)
	if req.Context().Err() != nil || !(notSent || replayable(req)) {
		return nil
	}
	again, rewindErr := rewound(req)
	if rewindErr != nil {
		return nil
	}
	return again
}

// errHTTP3Broken: the race left HTTP/3 out (see brokenHTTP3).
var errHTTP3Broken = errors.New("http3: broken for this server, not tried")

// HTTP3BrokenError wraps the error of an HTTP/3 request that marked HTTP/3 broken
// for the server: the session itself is fine (the next requests use TCP).
type HTTP3BrokenError struct{ Err error }

func (e *HTTP3BrokenError) Error() string { return e.Err.Error() }
func (e *HTTP3BrokenError) Unwrap() error { return e.Err }

// brokenHTTP3: Chrome's broken alternative service, per address. HTTP/3 stays out
// of races for 5 minutes, doubled on every failure after the entry expired (up
// to 2 days); a later HTTP/3 win forgets the entry.
type brokenHTTP3 struct {
	until    time.Time
	failures int
}

const brokenHTTP3Delay = 5 * time.Minute
const brokenHTTP3MaxDelay = 48 * time.Hour

// http3Broke tells a failure of HTTP/3 itself with this server - the connection
// closed with an error by either side, a QUIC protocol violation, a QPACK state the
// decoder cannot follow - from everything else: a request the server reset, our own
// cancellations and timeouts, a response refused for its size or fields, and a
// connection that went quiet or that the server forgot (idle timeout, stateless
// reset). Like Chrome, those get a new connection, not TCP.
func http3Broke(req *http.Request, err error) bool {
	if err == nil || req.Context().Err() != nil || errors.Is(err, errLostRace) || errors.Is(err, errClosed) ||
		errors.Is(err, http3.ErrTransportClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var h3err *http3.Error
	if errors.As(err, &h3err) {
		// closed by the server with an error, or by us over the server's misbehaviour;
		// a graceful close (H3_NO_ERROR, QUIC's 0, and unknown or reserved codes, which
		// RFC 9114 8.1 equates with H3_NO_ERROR) is not a failure
		return h3err.Connection && http3FailureCode(uint64(h3err.ErrorCode))
	}
	var app *quic.ApplicationError
	if errors.As(err, &app) {
		return http3FailureCode(uint64(app.ErrorCode))
	}
	var transport *quic.TransportError
	if errors.As(err, &transport) {
		return transport.ErrorCode != quic.NoError && transport.ErrorCode != quic.ApplicationErrorErrorCode
	}
	var version *quic.VersionNegotiationError
	var decompression *qpack.DecompressionError
	return errors.As(err, &version) || errors.As(err, &decompression)
}

// http3FailureCode: the HTTP/3 (RFC 9114 8.1) and QPACK (RFC 9204 6) error codes
// other than H3_NO_ERROR.
func http3FailureCode(code uint64) bool {
	return (code >= 0x101 && code <= 0x110) || (code >= 0x200 && code <= 0x202)
}

func (pr *protocolRacer) markHTTP3Broken(addr string) {
	pr.protocolCacheMu.Lock()
	defer pr.protocolCacheMu.Unlock()
	if pr.broken == nil {
		pr.broken = make(map[string]brokenHTTP3)
	}
	b := pr.broken[addr]
	if time.Now().Before(b.until) {
		return // already broken: concurrent failures count once
	}
	delay := brokenHTTP3Delay << min(b.failures, 9)
	if delay > brokenHTTP3MaxDelay {
		delay = brokenHTTP3MaxDelay
	}
	pr.broken[addr] = brokenHTTP3{until: time.Now().Add(delay), failures: b.failures + 1}
	if pr.protocolCache[addr] == "h3" {
		delete(pr.protocolCache, addr)
	}
}

func (pr *protocolRacer) http3Broken(addr string) bool {
	pr.protocolCacheMu.RLock()
	defer pr.protocolCacheMu.RUnlock()
	b, ok := pr.broken[addr]
	return ok && time.Now().Before(b.until)
}

// tryUseCachedProtocol returns the request to race with when there is no cached
// protocol or it failed in a way that allows sending the request again.
func (pr *protocolRacer) tryUseCachedProtocol(req *http.Request, addr string, getTransportFunc func(*http.Request, string) error) (*http.Response, error, *http.Request) {
	pr.protocolCacheMu.RLock()
	cachedProtocol, found := pr.protocolCache[addr]
	pr.protocolCacheMu.RUnlock()

	if !found {
		return nil, nil, req // No cache, proceed to racing
	}

	transport, err := pr.getOrCreateTransport(cachedProtocol, addr, req, getTransportFunc)
	if errors.Is(err, errClosed) {
		return nil, err, nil
	}
	if err != nil {
		pr.handleCachedProtocolError(err, addr, req)
		return nil, nil, req // Cached protocol failed, proceed to racing
	}

	resp, err := pr.roundTrip(transport, req, addr)
	if err == nil {
		return resp, nil, nil // Success!
	}
	var headerErr *http2.RequestHeaderError
	if errors.As(err, &headerErr) {
		return nil, err, nil // refused before sending: nothing wrong with the connection
	}

	if cachedProtocol == "h3" && http3Broke(req, err) {
		pr.markHTTP3Broken(addr)
		err = &HTTP3BrokenError{Err: err}
	}
	// Later requests race again, on new connections (in-flight requests keep
	// theirs): after an error, and for HTTP/3 after a timeout or cancellation too —
	// UDP gets black-holed far more often than TCP, and only a race tells a silent
	// path from a slow server. A slow HTTP/1.1 or HTTP/2 server keeps its connection.
	if req.Context().Err() == nil || cachedProtocol == "h3" {
		pr.clearProtocolCache(addr)
		pr.discardTransport(cachedProtocol, addr, transport)
	}
	// Racing sends this request again: only when that is safe (and still wanted).
	// A transport closed under the request (retired by a sibling's failure) refused
	// it before sending anything.
	retry := retryRequest(req, err)
	if retry == nil {
		return nil, err, nil
	}
	return nil, nil, retry
}

func (pr *protocolRacer) getOrCreateTransport(protocol, addr string, req *http.Request, getTransportFunc func(*http.Request, string) error) (http.RoundTripper, error) {
	transportKey := pr.getTransportKey(protocol, addr)

	pr.cachedTransportsLck.Lock()
	defer pr.cachedTransportsLck.Unlock()

	if pr.closed {
		return nil, errClosed
	}
	if transport, exists := pr.cachedTransports[transportKey]; exists {
		return transport, nil
	}

	transport, err := pr.createTransportForProtocol(protocol, addr, req, getTransportFunc)
	if err != nil {
		return nil, err
	}

	pr.cachedTransports[transportKey] = transport
	return transport, nil
}

func (pr *protocolRacer) createTransportForProtocol(protocol, addr string, req *http.Request, getTransportFunc func(*http.Request, string) error) (http.RoundTripper, error) {
	if protocol == "h3" {
		gate := newRaceGate()
		gate.claim("h3")
		return pr.newHTTP3(gate)
	}

	// For HTTP/2, use the standard transport creation
	transportKey := pr.getTransportKey(protocol, addr)
	if err := getTransportFunc(req, transportKey); err != nil {
		return nil, err
	}

	return pr.cachedTransports[transportKey], nil
}

func (pr *protocolRacer) startRace(req *http.Request, addr string, getTransportFunc func(*http.Request, string) error) (*http.Response, error) {
	gate := newRaceGate()
	h3Failed := make(chan struct{})
	resultCh := make(chan racingResult, 2)

	if pr.http3Broken(addr) {
		// HTTP/3 is broken for this server: TCP right away, nothing over UDP
		close(h3Failed)
		resultCh <- racingResult{protocol: "h3", err: errHTTP3Broken}
	} else {
		go pr.attemptHTTP3(req, gate, h3Failed, resultCh)
	}
	go pr.attemptHTTP2(req, addr, getTransportFunc, gate, h3Failed, resultCh)

	// only the winner sends the request, so both results come back promptly unless
	// the winner is still waiting for its response (bounded by the request context)
	var winnerErr, h2Err, h3Err error
	for i := 0; i < 2; i++ {
		result := <-resultCh
		if result.err == nil && result.response != nil {
			pr.cacheWinningProtocol(addr, result.protocol, result.transport)
			return result.response, nil
		}
		switch {
		case gate.won(result.protocol):
			winnerErr = result.err
			if result.protocol == "h3" && http3Broke(req, result.err) {
				pr.markHTTP3Broken(addr)
				winnerErr = &HTTP3BrokenError{Err: result.err}
			}
		case errors.Is(result.err, errLostRace):
		case result.protocol == "h2":
			h2Err = result.err
		default:
			h3Err = result.err
		}
	}

	// neither connected: the TCP error (refused, unreachable, TLS) says more than
	// QUIC's handshake timeout
	for _, err := range []error{winnerErr, h2Err, h3Err} {
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("http3 racing: both protocols failed to connect")
}

func (pr *protocolRacer) attemptHTTP3(req *http.Request, gate *raceGate, failed chan<- struct{}, resultCh chan<- racingResult) {
	if pr.isClosed() {
		close(failed)
		resultCh <- racingResult{protocol: "h3", err: errClosed}
		return
	}
	h3Transport, err := pr.newHTTP3(gate)
	if err != nil {
		close(failed)
		resultCh <- racingResult{protocol: "h3", err: fmt.Errorf("failed to build HTTP/3 transport: %w", err)}
		return
	}

	resp, err := h3Transport.RoundTrip(req)
	if err == nil {
		resultCh <- racingResult{protocol: "h3", response: resp, transport: h3Transport}
		return
	}
	_ = h3Transport.Close()
	close(failed)
	if !errors.Is(err, errLostRace) {
		err = fmt.Errorf("HTTP/3 request failed: %w", err)
	}
	resultCh <- racingResult{protocol: "h3", err: err}
}

func (pr *protocolRacer) attemptHTTP2(req *http.Request, addr string, getTransportFunc func(*http.Request, string) error, gate *raceGate, h3Failed <-chan struct{}, resultCh chan<- racingResult) {
	// Chrome-like 300ms delay before starting HTTP/2 (none once HTTP/3 has failed)
	// https://groups.google.com/a/chromium.org/g/proto-quic/c/igD7dLSct24
	delay := time.NewTimer(300 * time.Millisecond)
	defer delay.Stop()
	select {
	case <-delay.C:
	case <-h3Failed:
	case <-gate.done:
	case <-req.Context().Done():
		resultCh <- racingResult{protocol: "h2", err: context.Cause(req.Context())}
		return
	}
	if gate.lost("h2") {
		resultCh <- racingResult{protocol: "h2", err: errLostRace}
		return
	}

	// A cached transport has a working connection (a failed one is discarded before
	// a race); otherwise HTTP/2 claims the request only after its own TLS handshake.
	pr.cachedTransportsLck.Lock()
	if pr.closed {
		pr.cachedTransportsLck.Unlock()
		resultCh <- racingResult{protocol: "h2", err: errClosed}
		return
	}
	_, cached := pr.cachedTransports[addr]
	if !cached {
		// the dial is abandoned as soon as HTTP/3 wins
		dctx, cancel := gate.cancelOnLoss(req.Context(), "h2")
		err := getTransportFunc(req.WithContext(dctx), addr)
		cancel()
		if err != nil {
			pr.cachedTransportsLck.Unlock()
			if gate.lost("h2") {
				err = errLostRace
			}
			resultCh <- racingResult{protocol: "h2", err: err}
			return
		}
	}
	h2Transport := pr.cachedTransports[addr]
	won := gate.claim("h2")
	if !won && !cached && pr.cachedTransports[addr] == h2Transport {
		// built for this race only: no later race may take it for a connected one
		delete(pr.cachedTransports, addr)
	}
	pr.cachedTransportsLck.Unlock()

	if !won {
		if !cached && pr.discardConn != nil {
			pr.discardConn(addr)
		}
		resultCh <- racingResult{protocol: "h2", err: errLostRace}
		return
	}

	resp, err := pr.roundTrip(h2Transport, req, addr)
	resultCh <- racingResult{protocol: "h2", response: resp, err: err}
}

// roundTrip sends the request over transport and, when the dial underneath
// reports that the server has moved to a protocol this transport cannot speak,
// forgets the transport so the next attempt builds one that fits.
//
// Clearing the protocol cache alone does not recover from that: the race it
// falls back to reaches for the same cached transport and fails on the same
// mismatch, for every request from then on.
//
// addr is the dial address rather than the transport's cache key, because only
// the transport stored under that key dials through the round tripper. The
// HTTP/3 transport brings its own dialer and never reports this.
func (pr *protocolRacer) roundTrip(transport http.RoundTripper, req *http.Request, addr string) (*http.Response, error) {
	var resp *http.Response
	var err error
	if _, ok := transport.(*racedHTTP3); ok {
		resp, err = transport.RoundTrip(req) // counts its own uses
	} else {
		use := pr.usageOf(transport)
		use.begin()
		resp, err = use.track(transport.RoundTrip(req))
	}
	if err != nil && errors.Is(err, errProtocolChanged) {
		// forgotten and, once its last request is done, closed
		pr.discardTransport("", addr, transport)
	}

	return resp, err
}

// usageOf returns the use counter of an HTTP/1.1 or HTTP/2 transport.
func (pr *protocolRacer) usageOf(transport http.RoundTripper) *usage {
	if u, ok := pr.uses.Load(transport); ok {
		return u.(*usage)
	}
	u, _ := pr.uses.LoadOrStore(transport, &usage{})
	return u.(*usage)
}

func (pr *protocolRacer) getTransportKey(protocol, addr string) string {
	if protocol == "h3" {
		return addr + ":h3"
	}
	return addr
}

func (pr *protocolRacer) clearProtocolCache(addr string) {
	pr.protocolCacheMu.Lock()
	delete(pr.protocolCache, addr)
	pr.protocolCacheMu.Unlock()
}

// cacheWinningProtocol remembers the protocol and, for HTTP/3, keeps the transport
// that won (upstream cached a fresh one and leaked the winner with its connection).
func (pr *protocolRacer) cacheWinningProtocol(addr, protocol string, transport http.RoundTripper) {
	pr.protocolCacheMu.Lock()
	pr.protocolCache[addr] = protocol
	if protocol == "h3" {
		delete(pr.broken, addr) // HTTP/3 works again
	}
	pr.protocolCacheMu.Unlock()

	if protocol == "h3" && transport != nil {
		pr.cachedTransportsLck.Lock()
		_, exists := pr.cachedTransports[addr+":h3"]
		keep := !exists && !pr.closed
		if keep {
			pr.cachedTransports[addr+":h3"] = transport
		}
		pr.cachedTransportsLck.Unlock()
		if !keep {
			// a concurrent race won first, or the round tripper is closed: close
			// this one once its response is done
			closeTransport(transport)
		}
	}
}

// discardTransport forgets a cached transport that failed a request so the next
// race starts from new connections. Requests still using it are left alone: the
// transport is closed (HTTP/3) or has its idle connections closed (HTTP/1.1,
// HTTP/2) once they are done.
func (pr *protocolRacer) discardTransport(protocol, addr string, transport http.RoundTripper) {
	if protocol == "h3" {
		pr.cachedTransportsLck.Lock()
		if pr.cachedTransports[addr+":h3"] == transport {
			delete(pr.cachedTransports, addr+":h3")
		}
		pr.cachedTransportsLck.Unlock()
		closeTransport(transport)
		return
	}
	if pr.dropTransport != nil {
		pr.dropTransport(addr, transport)
	}
	pr.usageOf(transport).retire(func() {
		closeTransport(transport)
		pr.uses.Delete(transport)
	})
}

func (pr *protocolRacer) isClosed() bool {
	pr.cachedTransportsLck.Lock()
	defer pr.cachedTransportsLck.Unlock()
	return pr.closed
}

// close marks the racer closed (nothing is cached any more) and empties the
// protocol cache.
func (pr *protocolRacer) close() {
	pr.cachedTransportsLck.Lock()
	pr.closed = true
	pr.cachedTransportsLck.Unlock()
	pr.protocolCacheMu.Lock()
	pr.protocolCache = make(map[string]string)
	pr.protocolCacheMu.Unlock()
}

func (pr *protocolRacer) handleCachedProtocolError(err error, addr string, req *http.Request) {
	if errors.Is(err, ErrBadPinDetected) && pr.badPinHandlerFunc != nil {
		pr.badPinHandlerFunc(req)
	}
	pr.clearProtocolCache(addr)
}

func (pr *protocolRacer) getHTTP3Config() *http3Config {
	return &http3Config{
		clientSessionCache:     pr.clientSessionCache,
		insecureSkipVerify:     pr.insecureSkipVerify,
		serverNameOverwrite:    pr.serverNameOverwrite,
		transportOptions:       pr.transportOptions,
		http3Settings:          pr.http3Settings,
		http3SettingsOrder:     pr.http3SettingsOrder,
		http3PriorityParam:     pr.http3PriorityParam,
		http3PseudoHeaderOrder: pr.http3PseudoHeaderOrder,
		http3SendGreaseFrames:  pr.http3SendGreaseFrames,
		http3Fingerprint:       pr.http3Fingerprint,
		proxyURL:               pr.proxyURL,
	}
}

type racingResult struct {
	protocol  string
	response  *http.Response
	err       error
	transport http.RoundTripper // the HTTP/3 transport that served response
}
