package tls_client

// yumeclient: protocol racing races connections, not requests.
//
// Upstream sent the request over HTTP/3 and, 300 ms later, over HTTP/2 as well, and
// used whichever answered first: every request whose HTTP/3 response took longer than
// that reached the server twice (both reading the one request body), and the losing
// attempt was left running. Here the first protocol to have a connection claims the
// request (an HTTP/3 connection counts once its handshake is complete, so a 0-RTT
// connection cannot claim it early); the other gives up before sending anything.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/httptrace"
	quic "github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/http3"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// errClosed: the round tripper was closed (its session removed); nothing was sent.
var errClosed = errors.New("tls-client: session is closed")

// errLostRace: the other protocol connected first; this attempt sent nothing.
var errLostRace = errors.New("http3 racing: the other protocol connected first")

type raceGate struct {
	once   sync.Once
	winner string
	done   chan struct{}
}

func newRaceGate() *raceGate { return &raceGate{done: make(chan struct{})} }

// claim makes protocol the winner unless another one already is.
func (g *raceGate) claim(protocol string) bool {
	g.once.Do(func() { g.winner = protocol; close(g.done) })
	return g.winner == protocol
}

func (g *raceGate) decided() bool {
	select {
	case <-g.done:
		return true
	default:
		return false
	}
}

func (g *raceGate) won(protocol string) bool { return g.decided() && g.winner == protocol }

func (g *raceGate) lost(protocol string) bool { return g.decided() && g.winner != protocol }

// cancelOnLoss returns ctx, cancelled once another protocol wins.
func (g *raceGate) cancelOnLoss(ctx context.Context, protocol string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-g.done:
			if g.winner != protocol {
				cancel()
			}
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// usage counts the requests a transport serves, each until its response body is
// closed, so the transport can be closed once they are done instead of under them.
// Once retired its close runs whenever it is idle (a request that took the
// transport just before it was retired is cleaned up after too).
type usage struct {
	mu     sync.Mutex
	active int
	onIdle func()
}

func (u *usage) begin() {
	u.mu.Lock()
	u.active++
	u.mu.Unlock()
}

func (u *usage) end() {
	u.mu.Lock()
	u.active--
	fn := u.takeIdleLocked()
	u.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (u *usage) takeIdleLocked() func() {
	if u.active > 0 {
		return nil
	}
	return u.onIdle
}

// retire runs fn now when nothing is in use, otherwise when the last use ends (and
// again after any later use). Only the first call counts; fn must be idempotent.
func (u *usage) retire(fn func()) {
	u.mu.Lock()
	if u.onIdle != nil {
		u.mu.Unlock()
		return
	}
	u.onIdle = fn
	fn = u.takeIdleLocked()
	u.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// track ends the use begun for a round trip when it failed, or when the response
// body is closed.
func (u *usage) track(resp *http.Response, err error) (*http.Response, error) {
	if err != nil || resp == nil || resp.Body == nil {
		u.end()
		return resp, err
	}
	resp.Body = &endOnClose{ReadCloser: resp.Body, end: u.end}
	return resp, nil
}

type endOnClose struct {
	io.ReadCloser
	once sync.Once
	end  func()
}

func (b *endOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.end)
	return err
}

// racedHTTP3 is an HTTP/3 transport whose dials go through a race gate. With its own
// Dial an http3.Transport opens no UDP socket, so this one owns it; Close releases it
// (CloseIdleConnections alone left every transport's socket and its goroutines behind).
type racedHTTP3 struct {
	socks string // SOCKS5 proxy whose UDP relay carries the QUIC packets
	*http3.Transport
	use    usage
	mu     sync.Mutex
	udp    *quic.Transport
	closed bool

	// with a fingerprint every connection has its own socket (Chrome's connection
	// IDs are empty), and later connections announce the RTT measured before
	fp      *profiles.HTTP3Fingerprint
	sockets map[net.PacketConn]struct{}
	rtts    map[string]time.Duration
}

// newHTTP3 builds a gated HTTP/3 transport (an already decided gate for a transport
// that is not racing).
func (pr *protocolRacer) newHTTP3(gate *raceGate) (*racedHTTP3, error) {
	cfg := pr.getHTTP3Config()
	built, err := buildHTTP3Transport(cfg)
	if err != nil {
		return nil, err
	}
	t3 := built.(*http3.Transport)
	var socks string
	if pr.http3Fingerprint != nil && cfg.proxyURL != "" {
		// a fingerprinted profile dials the SOCKS5 relay itself: the stock SOCKS5 QUIC
		// dialer gave every connection a 4-byte source connection ID (Chrome: none), no
		// google_initial_rtt and no trace events for the stage timeouts
		socks, t3.Dial = cfg.proxyURL, nil
	}
	r := newRacedHTTP3(t3, gate, pr.http3Fingerprint)
	r.socks = socks
	return r, nil
}

func (r *racedHTTP3) RoundTrip(req *http.Request) (*http.Response, error) {
	r.use.begin()
	return r.use.track(r.Transport.RoundTrip(req))
}

// CloseIdleConnections: quic-go counts a connection idle as soon as RoundTrip has
// returned, with its response body possibly still being read, so connections are
// only closed here while no response is open.
func (r *racedHTTP3) CloseIdleConnections() {
	r.use.mu.Lock() // a request beginning meanwhile waits: its connection stays
	defer r.use.mu.Unlock()
	if r.use.active == 0 {
		r.Transport.CloseIdleConnections()
	}
}

// retire closes the transport once no response it served is open any more.
func (r *racedHTTP3) retire() {
	r.use.retire(func() { _ = r.Close() })
}

func newRacedHTTP3(t3 *http3.Transport, gate *raceGate, fp *profiles.HTTP3Fingerprint) *racedHTTP3 {
	r := &racedHTTP3{Transport: t3, fp: fp}
	dial := t3.Dial
	if dial == nil {
		dial = r.dialUDP
		if fp != nil {
			dial = r.dialOwnSocket
		}
	}
	t3.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		if gate.lost("h3") {
			return nil, errLostRace
		}
		if gate.won("h3") {
			return dial(ctx, addr, tlsCfg, cfg) // a later connection of the winner
		}
		dctx, cancel := gate.cancelOnLoss(ctx, "h3")
		defer cancel()
		conn, err := dial(dctx, addr, tlsCfg, cfg)
		if err != nil {
			if gate.lost("h3") {
				return nil, errLostRace
			}
			return nil, err
		}
		// DialEarly returns before the handshake when 0-RTT is possible: claim only
		// for a connection that is really there
		select {
		case <-conn.HandshakeComplete():
		case <-conn.Context().Done():
			if gate.lost("h3") {
				return nil, errLostRace
			}
			return nil, context.Cause(conn.Context())
		case <-dctx.Done():
			_ = conn.CloseWithError(0, "")
			if gate.lost("h3") {
				return nil, errLostRace
			}
			return nil, context.Cause(dctx)
		}
		if !gate.claim("h3") {
			_ = conn.CloseWithError(0, "")
			return nil, errLostRace
		}
		return conn, nil
	}
	return r
}

// dialUDP is http3.Transport's default dial (resolve, then DialEarly on a shared UDP
// socket) with the same trace events.
func (r *racedHTTP3) dialUDP(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, http3.ErrTransportClosed
	}
	if r.udp == nil {
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
		r.udp = &quic.Transport{Conn: udpConn}
	}
	udp := r.udp
	r.mu.Unlock()

	udpAddr, err := resolveRaceUDPAddr(ctx, addr)
	if err != nil {
		return nil, err
	}
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.ConnectStart != nil {
		trace.ConnectStart("udp", udpAddr.String())
	}
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
	conn, err := udp.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	var state tls.ConnectionState
	if conn != nil {
		state = conn.ConnectionState().TLS
	}
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(state, err)
	}
	if trace != nil && trace.ConnectDone != nil {
		trace.ConnectDone("udp", udpAddr.String(), err)
	}
	return conn, err
}

func resolveRaceUDPAddr(ctx context.Context, addr string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, err
	}
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.DNSStart != nil {
		trace.DNSStart(httptrace.DNSStartInfo{Host: host})
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if trace != nil && trace.DNSDone != nil {
		trace.DNSDone(httptrace.DNSDoneInfo{Addrs: ips, Err: err})
	}
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	want6 := strings.ContainsRune(addr, '[') // an IPv6 literal; IPv4 preferred otherwise
	ip := ips[0]
	for _, candidate := range ips {
		if (candidate.IP.To4() == nil) == want6 {
			ip = candidate
			break
		}
	}
	return &net.UDPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}, nil
}

// Close closes the transport, its connections and its UDP socket.
func (r *racedHTTP3) Close() error {
	err := r.Transport.Close()
	r.mu.Lock()
	udp := r.udp
	sockets := r.sockets
	r.udp, r.sockets, r.closed = nil, nil, true
	r.mu.Unlock()
	if udp != nil {
		_ = udp.Close()
		_ = udp.Conn.Close()
	}
	for s := range sockets {
		_ = s.Close()
	}
	return err
}

// dialOwnSocket dials a fingerprinted connection from a socket of its own, as
// browsers do, with the fingerprint's connection ID length.
func (r *racedHTTP3) dialOwnSocket(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	var udpAddr *net.UDPAddr
	var err error
	if r.socks == "" {
		if udpAddr, err = resolveRaceUDPAddr(ctx, addr); err != nil {
			return nil, err
		}
	} else {
		udpAddr = &net.UDPAddr{IP: net.IPv4zero} // replaced by dialSOCKS5Relay
	}
	network := "udp4"
	if udpAddr.IP.To4() == nil {
		network = "udp6"
	}
	var sock net.PacketConn
	if r.socks != "" {
		sock, udpAddr, err = dialSOCKS5Relay(ctx, r.socks, addr)
	} else {
		sock, err = net.ListenUDP(network, nil)
	}
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = sock.Close()
		return nil, http3.ErrTransportClosed
	}
	if r.sockets == nil {
		r.sockets = make(map[net.PacketConn]struct{})
	}
	r.sockets[sock] = struct{}{}
	rtt := r.rtts[addr]
	r.mu.Unlock()
	release := func() {
		r.mu.Lock()
		delete(r.sockets, sock)
		r.mu.Unlock()
		_ = sock.Close()
	}
	cfg = withInitialRTT(cfg, rtt)

	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.ConnectStart != nil {
		trace.ConnectStart("udp", udpAddr.String())
	}
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
	var conn *quic.Conn
	var tr *quic.Transport
	if r.fp.SrcConnIDLen == 0 {
		conn, err = quic.DialEarly(ctx, sock, udpAddr, tlsCfg, cfg)
	} else {
		tr = &quic.Transport{Conn: sock, ConnectionIDLength: r.fp.SrcConnIDLen}
		conn, err = tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}
	var state tls.ConnectionState
	if conn != nil {
		state = conn.ConnectionState().TLS
	}
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(state, err)
	}
	if trace != nil && trace.ConnectDone != nil {
		trace.ConnectDone("udp", udpAddr.String(), err)
	}
	if err != nil {
		if tr != nil {
			_ = tr.Close()
		}
		release()
		return nil, err
	}
	go func() {
		select {
		case <-conn.HandshakeComplete():
			r.noteRTT(addr, conn)
		case <-conn.Context().Done():
		}
		<-conn.Context().Done()
		r.noteRTT(addr, conn)
		if tr != nil {
			_ = tr.Close()
		}
		release()
	}()
	return conn, nil
}

func (r *racedHTTP3) noteRTT(addr string, conn *quic.Conn) {
	rtt := conn.ConnectionStats().SmoothedRTT
	if rtt <= 0 {
		return
	}
	r.mu.Lock()
	if r.rtts == nil {
		r.rtts = make(map[string]time.Duration)
	}
	r.rtts[addr] = rtt
	r.mu.Unlock()
}

// withInitialRTT fills in the optional google_initial_rtt transport parameter
// (microseconds) Chrome sends on later connections to a server.
func withInitialRTT(cfg *quic.Config, rtt time.Duration) *quic.Config {
	if cfg == nil || cfg.Fingerprint == nil || rtt <= 0 {
		return cfg
	}
	fp := *cfg.Fingerprint
	fp.TransportParameters = append([]quic.TransportParameter(nil), fp.TransportParameters...)
	changed := false
	for i, tp := range fp.TransportParameters {
		if tp.ID == 0x3127 && tp.Optional {
			fp.TransportParameters[i].Value = uint64(rtt / time.Microsecond)
			changed = true
		}
	}
	if !changed {
		return cfg
	}
	c := cfg.Clone()
	c.Fingerprint = &fp
	return c
}

// closeTransport closes an HTTP/3 transport (its UDP socket too) once its open
// responses are done and closes the idle connections of any other.
func closeTransport(t http.RoundTripper) {
	switch c := t.(type) {
	case *racedHTTP3:
		c.retire()
	case interface{ Close() error }:
		_ = c.Close()
	case interface{ CloseIdleConnections() }:
		c.CloseIdleConnections()
	}
}

// replayable: a request that may be sent again after a failure (net/http's rule).
func replayable(req *http.Request) bool {
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return false
	}
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	for key := range req.Header {
		if strings.EqualFold(key, "Idempotency-Key") || strings.EqualFold(key, "X-Idempotency-Key") {
			return true
		}
	}
	return false
}

// rewound returns req with a fresh body for sending it again.
func rewound(req *http.Request) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("request body cannot be sent again")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	copied := *req
	copied.Body = body
	return &copied, nil
}

// dialSOCKS5Relay opens a UDP ASSOCIATE session with the SOCKS5 proxy and returns the
// packet conn that wraps every datagram for its relay, with the target resolved here
// (quic-go needs an address; the DNS query is local, as in the stock dialer).
func dialSOCKS5Relay(ctx context.Context, proxyURL, addr string) (net.PacketConn, *net.UDPAddr, error) {
	proxyAddr, auth, err := parseSOCKS5ProxyURL(proxyURL)
	if err != nil {
		return nil, nil, fmt.Errorf("socks5 quic dialer: %w", err)
	}
	local, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("socks5 quic dialer: failed to create UDP socket: %w", err)
	}
	control, relay, err := socks5UDPAssociate(ctx, proxyAddr, auth, local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		_ = local.Close()
		return nil, nil, fmt.Errorf("socks5 quic dialer: %w", err)
	}
	conn := &socks5PacketConn{udpConn: local, controlConn: control, relayAddr: relay}
	target, err := resolveUDPAddr(ctx, addr, relay.IP)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("socks5 quic dialer: failed to resolve target %q: %w", addr, err)
	}
	return conn, target, nil
}
