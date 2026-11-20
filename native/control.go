package main

// Request lifecycle control (0.5.0): every native call carries a requestId that
// Python can cancel through yumeclient_cancel, split timeouts (connect / write /
// read / total) enforced through one cancellable context, structured error
// kinds instead of bare strings, and per-phase timings for connection_info.
//
// Stages of one hop (one RoundTrip; redirects start a new hop):
//
//	hop start ──connect──> GotConn ──write──> WroteRequest ──read──> first byte
//	                                                   body reads ──read (idle)──>
//
// The connect stage starts when the hop starts (before tls-client dials a new
// host from inside RoundTrip), so it covers DNS, proxy CONNECT, TCP and TLS.

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/fhttp/httptrace"
	tls_client "github.com/bogdanfinn/tls-client"
	tls "github.com/bogdanfinn/utls"

	"golang.org/x/net/http/httpguts"
)

// requestOptions: per-request fields read from the raw payload (not part of
// upstream's RequestInput).
type requestOptions struct {
	RequestId    string `json:"requestId"`
	TotalMs      int64  `json:"totalTimeoutMilliseconds"`
	ConnectMs    int64  `json:"connectTimeoutMilliseconds"`
	ReadMs       int64  `json:"readTimeoutMilliseconds"`
	WriteMs      int64  `json:"writeTimeoutMilliseconds"`
	Stream       bool   `json:"stream"`
	MaxBodyBytes int64  `json:"maxBodyBytes"`
	// Jar: snapshot of the Python CookieJar (the source of truth), see cookiejar.go
	Jar []seedCookie `json:"jar"`
	// RequireProtocol: ALPN every TLS connection must have negotiated ("h2" for
	// http_version="2"); anything else is closed before the request is written
	RequireProtocol string `json:"requireProtocol"`
	// H2Headers: fields sent only over HTTP/2, after the request's own unless it has
	// them (Chrome's "priority"); third_party/patches/fhttp.patch WithExtraHeaders
	H2Headers [][2]string `json:"h2Headers"`
	// OmitHeaders: header names the request removed (headers={"X": None}); sent on no
	// hop, including the ones a transport adds when absent (HTTP/3 "priority")
	OmitHeaders []string `json:"omitHeaders"`
}

func decodeRequestOptions(raw []byte) requestOptions {
	var o requestOptions
	_ = json.Unmarshal(raw, &o)
	// HTTP/2 fields go out as raw HPACK (the transport validates only req.Header)
	valid := o.H2Headers[:0]
	for _, kv := range o.H2Headers {
		if httpguts.ValidHeaderFieldName(kv[0]) && kv[0] == strings.ToLower(kv[0]) && httpguts.ValidHeaderFieldValue(kv[1]) {
			valid = append(valid, kv)
		}
	}
	o.H2Headers = valid
	return o
}

func msDuration(ms int64) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

var errCancelled = errors.New("request cancelled")

type stageTimeout struct {
	stage string // connect | write | read | total
	limit time.Duration
}

func (e *stageTimeout) Error() string {
	if e.stage == "body" {
		return fmt.Sprintf("read timeout (%s) exceeded while reading the body", e.limit)
	}
	return fmt.Sprintf("%s timeout (%s) exceeded", e.stage, e.limit)
}

func (e *stageTimeout) kind() string {
	switch e.stage {
	case "total":
		return "timeout"
	case "body":
		return "read_timeout"
	}
	return e.stage + "_timeout"
}
func (e *stageTimeout) Timeout() bool { return true }

type bodyTooLarge struct{ limit int64 }

func (e *bodyTooLarge) Error() string {
	return fmt.Sprintf("response body exceeds max_content_size (%d bytes)", e.limit)
}

// protocolMismatch: the TLS connection negotiated another protocol than the
// session requires (http_version="2" against an HTTP/1.1-only server).
type protocolMismatch struct{ want, got, addr string }

func (e *protocolMismatch) Error() string {
	got := "no ALPN (HTTP/1.1)"
	if e.got != "" {
		got = fmt.Sprintf("ALPN %q", e.got)
	}
	return fmt.Sprintf("http_version=2: server %s negotiated %s instead of %q; the connection was closed "+
		"before the request was sent (http_version='auto' follows the server's choice)", e.addr, got, e.want)
}

// proxyDialError marks failures of the proxy leg (dial to proxy, TLS to an
// https proxy, CONNECT / SOCKS negotiation).
type proxyDialError struct{ err error }

func (e *proxyDialError) Error() string { return "proxy: " + e.err.Error() }
func (e *proxyDialError) Unwrap() error { return e.err }

// ---------------------------------------------------------------------------
// per-request controller
// ---------------------------------------------------------------------------

type reqControl struct {
	id     string
	ctx    context.Context
	cancel context.CancelCauseFunc
	// release ends the request's use of its session (see holdSession), once
	release func()

	connect, write, read, total time.Duration
	// stageTimers=false for protocol-racing sessions: quic-go's HTTP/3 transport
	// does not report fhttp trace events, so connect/write timers could fire on
	// a healthy h3 exchange. Total and body-read timeouts still apply.
	stageTimers bool
	// jar: per-request cookie jar consulted by hopTransport on every hop
	jar *requestJar
	// requireProto: see requestOptions.RequireProtocol
	requireProto string
	// follow: the client follows redirects; every redirect response a hop gets
	// is recorded in history (Response.history), the final one filtered out later
	follow  bool
	omit    []string // requestOptions.OmitHeaders
	history []hopRecord

	mu         sync.Mutex
	timer      *time.Timer
	gen        uint64
	stage      string
	totalTimer *time.Timer
	finished   bool

	// dialing>0 while a proxy dialer runs: upstream's CONNECT request reuses the
	// request context, so its trace events must not advance our stages
	dialing atomic.Int32

	start, hopStart, gotConn, wrote, firstByte, hopEnd, bodyDone time.Time
	proxyStart, proxyDone                                        time.Time
	remote, local                                                string
}

func newReqControl(id string, opts requestOptions, racing, follow bool) *reqControl {
	ctx, cancel := context.WithCancelCause(context.Background())
	c := &reqControl{id: id, ctx: ctx, cancel: cancel, stageTimers: !racing, requireProto: opts.RequireProtocol, follow: follow, omit: opts.OmitHeaders,
		connect: msDuration(opts.ConnectMs), write: msDuration(opts.WriteMs),
		read: msDuration(opts.ReadMs), total: msDuration(opts.TotalMs),
		stage: "connect", start: time.Now()}
	if c.total > 0 {
		limit := c.total
		c.totalTimer = time.AfterFunc(limit, func() { c.cancel(&stageTimeout{stage: "total", limit: limit}) })
	}
	return c
}

// arm switches the current stage and (re)starts its timer; d<=0 only records
// the stage.
func (c *reqControl) arm(stage string, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armLocked(stage, d)
}

func (c *reqControl) armLocked(stage string, d time.Duration) {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.gen++
	c.stage = stage
	if d <= 0 || c.finished {
		return
	}
	gen, limit, name := c.gen, d, stage
	c.timer = time.AfterFunc(d, func() {
		c.mu.Lock()
		live := gen == c.gen && !c.finished
		c.mu.Unlock()
		if live {
			c.cancel(&stageTimeout{stage: name, limit: limit})
		}
	})
}

func (c *reqControl) currentStage() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stage
}

// headersDone: response headers are in. In stream mode the total deadline only
// covers the exchange up to here; the body is then bounded by the idle read
// timeout (falling back to the total value) so long downloads keep working.
func (c *reqControl) headersDone(stream bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hopEnd = time.Now()
	c.armLocked("body", 0)
	if stream && c.totalTimer != nil {
		c.totalTimer.Stop()
		if c.read <= 0 {
			c.read = c.total
		}
	}
}

func (c *reqControl) finish() {
	c.mu.Lock()
	c.finished = true
	if c.timer != nil {
		c.timer.Stop()
	}
	if c.totalTimer != nil {
		c.totalTimer.Stop()
	}
	if c.bodyDone.IsZero() {
		c.bodyDone = time.Now()
	}
	release := c.release
	c.release = nil
	c.mu.Unlock()
	c.cancel(nil) // release the context; a nil cause after completion is a no-op for callers
	if release != nil {
		release()
	}
}

func (c *reqControl) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if c.dialing.Load() > 0 {
				return
			}
			// plain http:// connections carry no ALPN and stay HTTP/1.1 (no h2c)
			proto := ""
			if info.Conn != nil {
				if cs, ok := info.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
					proto = cs.ConnectionState().NegotiatedProtocol
				}
			}
			if c.requireProto != "" && proto != c.requireProto {
				if _, isTLS := info.Conn.(interface{ ConnectionState() tls.ConnectionState }); isTLS {
					addr := ""
					if a := info.Conn.RemoteAddr(); a != nil {
						addr = a.String()
					}
					c.cancel(&protocolMismatch{want: c.requireProto, got: proto, addr: addr})
					_ = info.Conn.Close() // GotConn precedes the write: nothing reaches the server
					return
				}
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			c.gotConn = time.Now()
			if info.Reused {
				// a dial this hop started may have lost the race to a freed idle
				// connection: its proxy time does not belong to the connection used
				c.proxyStart, c.proxyDone = time.Time{}, time.Time{}
			}
			if info.Conn != nil {
				if a := info.Conn.RemoteAddr(); a != nil {
					c.remote = a.String()
				}
				if a := info.Conn.LocalAddr(); a != nil {
					c.local = a.String()
				}
			}
			if c.stageTimers {
				c.armLocked("write", c.write)
			} else {
				c.armLocked("write", 0)
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			if c.dialing.Load() > 0 {
				return
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			c.wrote = time.Now()
			if c.stageTimers {
				c.armLocked("read", c.read)
			} else {
				c.armLocked("read", 0)
			}
		},
		GotFirstResponseByte: func() {
			if c.dialing.Load() > 0 {
				return
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			c.firstByte = time.Now()
			c.armLocked("headers", 0)
		},
	}
}

func (c *reqControl) hopBegin() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hopStart = time.Now()
	c.gotConn, c.wrote, c.firstByte = time.Time{}, time.Time{}, time.Time{}
	c.proxyStart, c.proxyDone = time.Time{}, time.Time{}
	c.remote, c.local = "", ""
	if c.stageTimers {
		c.armLocked("connect", c.connect)
	} else {
		c.armLocked("connect", 0)
	}
}

// proxyDial brackets the proxy leg of a dial (TCP to the proxy + CONNECT/SOCKS).
func (c *reqControl) proxyDial(start bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if start {
		c.proxyStart, c.proxyDone = time.Now(), time.Time{}
	} else if !c.proxyStart.IsZero() {
		c.proxyDone = time.Now()
	}
}

func (c *reqControl) hopReturned() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stage == "connect" || c.stage == "write" || c.stage == "read" {
		c.armLocked("headers", 0) // transport without trace events (h3)
	}
}

func seconds(a, b time.Time) any {
	if a.IsZero() || b.IsZero() || b.Before(a) {
		return nil
	}
	return b.Sub(a).Seconds()
}

// timings: phases of the final hop; they add up to "total" (redirects holds
// everything before the final hop started).
func (c *reqControl) timings() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	end := c.bodyDone
	if end.IsZero() {
		end = time.Now()
	}
	out := map[string]any{"total": end.Sub(c.start).Seconds(), "redirects": seconds(c.start, c.hopStart)}
	headersAt := c.firstByte
	if headersAt.IsZero() {
		headersAt = c.hopEnd
	}
	if !c.gotConn.IsZero() {
		out["connect"] = seconds(c.hopStart, c.gotConn)
		if !c.wrote.IsZero() {
			out["write"] = seconds(c.gotConn, c.wrote)
			out["wait"] = seconds(c.wrote, c.hopEnd)
		} else {
			out["write"], out["wait"] = nil, seconds(c.gotConn, c.hopEnd)
		}
	} else {
		out["connect"], out["write"] = nil, nil
		out["wait"] = seconds(c.hopStart, c.hopEnd)
	}
	// proxy: part of connect spent reaching the target through the proxy (nil when the
	// hop reused a connection or went direct)
	out["proxy"] = seconds(c.proxyStart, c.proxyDone)
	out["first_byte"] = seconds(c.start, headersAt)
	out["body"] = seconds(c.hopEnd, end)
	return out
}

func (c *reqControl) addresses() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote, c.local
}

// ---------------------------------------------------------------------------
// registry + cancellation export
// ---------------------------------------------------------------------------

type inflightEntry struct {
	ctl         *reqControl
	cancelledAt time.Time // tombstone: cancel arrived before the call registered
}

var inflight = struct {
	sync.Mutex
	m map[string]*inflightEntry
}{m: map[string]*inflightEntry{}}

// register returns false when the request was cancelled before it started.
func registerRequest(c *reqControl) bool {
	if c.id == "" {
		return true
	}
	inflight.Lock()
	defer inflight.Unlock()
	if e, ok := inflight.m[c.id]; ok && e.ctl == nil {
		delete(inflight.m, c.id)
		return false
	}
	inflight.m[c.id] = &inflightEntry{ctl: c}
	return true
}

func unregisterRequest(c *reqControl) {
	if c.id == "" {
		return
	}
	inflight.Lock()
	if e, ok := inflight.m[c.id]; ok && e.ctl == c {
		delete(inflight.m, c.id)
	}
	inflight.Unlock()
}

func cancelRequest(id string) bool {
	if id == "" {
		return false
	}
	inflight.Lock()
	e, ok := inflight.m[id]
	if !ok {
		now := time.Now()
		if len(inflight.m) > 256 { // drop stale tombstones (calls that never started)
			for k, v := range inflight.m {
				if v.ctl == nil && now.Sub(v.cancelledAt) > 5*time.Minute {
					delete(inflight.m, k)
				}
			}
		}
		inflight.m[id] = &inflightEntry{cancelledAt: now}
		inflight.Unlock()
		return false
	}
	inflight.Unlock()
	if e.ctl != nil {
		e.ctl.cancel(errCancelled)
	}
	return true
}

// yumeclient_debug_stats: live native bookkeeping for leak tests.
//
//export yumeclient_debug_stats
func yumeclient_debug_stats() *C.char {
	inflight.Lock()
	active, tombstones := 0, 0
	for _, e := range inflight.m {
		if e.ctl != nil {
			active++
		} else {
			tombstones++
		}
	}
	inflight.Unlock()
	streams.Lock()
	open := len(streams.m)
	streams.Unlock()
	return jsonOut(map[string]any{"inflight": active, "tombstones": tombstones, "streams": open,
		"goroutines": runtime.NumGoroutine()})
}

//export yumeclient_cancel
func yumeclient_cancel(requestId *C.char) C.int {
	if cancelRequest(C.GoString(requestId)) {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// transport hooks
// ---------------------------------------------------------------------------

type controlKey struct{}

func controlFrom(ctx context.Context) *reqControl {
	c, _ := ctx.Value(controlKey{}).(*reqControl)
	return c
}

// hopTransport is the outermost RoundTripper of every session: http.Client
// calls it once per hop (redirects included), before tls-client dials.
type hopTransport struct {
	inner http.RoundTripper
	use   inUse
}

// inUse counts a session's requests, each from RoundTrip until its response body
// is closed, so closing the session can wait for them: a session is removed after
// any failed request, and closing its transports at once broke the other requests
// still running on it.
type inUse struct {
	mu      sync.Mutex
	active  int
	onIdle  func()
	closing bool
}

// acquire begins a use for a whole call unless the session is already closing.
func (u *inUse) acquire() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closing {
		return false
	}
	u.active++
	return true
}

func (u *inUse) begin() {
	u.mu.Lock()
	u.active++
	u.mu.Unlock()
}

func (u *inUse) end() {
	u.mu.Lock()
	u.active--
	var fn func()
	if u.active == 0 {
		fn, u.onIdle = u.onIdle, nil
	}
	u.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// whenIdle runs fn now when no request is running, otherwise after the last one.
// The session counts as closing from now on.
func (u *inUse) whenIdle(fn func()) {
	u.mu.Lock()
	u.closing = true
	if u.active > 0 {
		if prev := u.onIdle; prev != nil {
			u.onIdle = func() { prev(); fn() }
		} else {
			u.onIdle = fn
		}
		u.mu.Unlock()
		return
	}
	u.mu.Unlock()
	fn()
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

// CloseIdleConnections lets http.Client.CloseIdleConnections (session close) reach the
// tls-client transports: without it a closed session kept its HTTP/2 connections and
// their read loops until the server hung up.
func (h *hopTransport) CloseIdleConnections() {
	if c, ok := h.inner.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// Close fully closes the transports underneath (HTTP/3 UDP sockets included).
func (h *hopTransport) Close() {
	if c, ok := h.inner.(interface{ Close() }); ok {
		c.Close()
	} else {
		h.CloseIdleConnections()
	}
}

func (h *hopTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h.use.begin()
	resp, err := h.roundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		h.use.end()
		return resp, err
	}
	resp.Body = &endOnClose{ReadCloser: resp.Body, end: h.use.end}
	return resp, nil
}

func (h *hopTransport) roundTrip(req *http.Request) (*http.Response, error) {
	c := controlFrom(req.Context())
	cloned := false
	if c != nil {
		c.hopBegin()
		// cookie handling moved here from http.Client.Jar (which is nil now): same
		// AddCookie / SetCookies steps the client performs, but on the per-request jar
		if c.jar != nil {
			if cookies := c.jar.Cookies(req.URL); len(cookies) > 0 {
				req, cloned = req.Clone(req.Context()), true
				for _, ck := range cookies {
					req.AddCookie(ck)
				}
			}
		}
	}
	// a key without values: no field on HTTP/1.1 and HTTP/2, and the HTTP/2 extra
	// headers (fhttp.patch) and HTTP/3 transport do not add their own either
	if c != nil && len(c.omit) > 0 {
		if !cloned {
			req, cloned = req.Clone(req.Context()), true
		}
		if req.Header == nil {
			req.Header = http.Header{}
		}
		for _, name := range c.omit {
			for key := range req.Header {
				if strings.EqualFold(key, name) {
					delete(req.Header, key)
				}
			}
			req.Header[http.CanonicalHeaderKey(name)] = []string{}
		}
	}
	// fhttp adds "Go-http-client/1.1" unless the exact key "User-Agent" or
	// "user-agent" is present (so also next to an application "USER-AGENT"), and
	// "Go-http-client/2.0" on h2 unless some spelling is. A key without values
	// means "omit" to HTTP/1.1, HTTP/2 (third_party/patches/fhttp.patch) and HTTP/3.
	if req.Header["User-Agent"] == nil && req.Header["user-agent"] == nil {
		if !cloned {
			req = req.Clone(req.Context())
		}
		if req.Header == nil {
			req.Header = http.Header{}
		}
		req.Header["User-Agent"] = []string{}
	}
	resp, err := h.inner.RoundTrip(req)
	if c != nil && err == nil {
		c.hopReturned()
		if c.jar != nil {
			if rc := resp.Cookies(); len(rc) > 0 {
				c.jar.SetCookies(req.URL, rc)
			}
		}
		if c.follow && followsRedirect(req, resp) {
			c.recordHop(req, resp)
		}
	}
	return resp, err
}

// omits: the request removed this header (headers={name: None}).
func (c *reqControl) omits(name string) bool {
	for _, n := range c.omit {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// hopRecord: one redirect response of the request (Response.history).
type hopRecord struct {
	resp    *http.Response
	method  string
	url     string
	status  int
	proto   string
	header  http.Header
	cookies map[string]string
	body    []byte // decoded; nil when larger than historyBodyLimit
	elapsed float64
}

// historyBodyLimit: redirect bodies up to this size (raw and decoded) are kept.
// The capture is best effort and never holds the redirect up for long: a pause
// longer than historyStallLimit (or the read timeout, if shorter) or a capture
// longer than historyCaptureLimit drops the body (content b"") and the redirect is
// followed. (Go's client itself only drains up to 2 KiB before following; requests
// reads the whole body under the read timeout.) Content-Length is usually gone by
// now (fhttp drops it when it added Accept-Encoding), so it only skips the read when
// it is still present.
const (
	historyBodyLimit    = 64 << 10
	historyStallLimit   = 500 * time.Millisecond
	historyCaptureLimit = 2 * time.Second
)

// followsRedirect: the responses http.Client follows (net/http redirectBehavior):
// 301/302/303, and 307/308 when the body can be sent again. Only these are recorded
// in Response.history; any other 3xx is the final response and keeps its body.
func followsRedirect(req *http.Request, resp *http.Response) bool {
	if resp.Header.Get("Location") == "" {
		return false
	}
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
		return true
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		// decided on the first request; a follow-up hop exists only if it could be
		// replayed (the hop itself carries no GetBody)
		noBody := req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0
		return req.GetBody != nil || noBody || req.Response != nil
	}
	return false
}

func (c *reqControl) recordHop(req *http.Request, resp *http.Response) {
	rec := hopRecord{resp: resp, method: req.Method, url: req.URL.String(), status: resp.StatusCode,
		proto: resp.Proto, header: resp.Header.Clone(), cookies: map[string]string{}}
	for _, ck := range resp.Cookies() {
		rec.cookies[ck.Name] = ck.Value
	}
	c.mu.Lock()
	if !c.hopStart.IsZero() {
		rec.elapsed = time.Since(c.hopStart).Seconds() // this hop, up to its headers (as requests)
	}
	c.mu.Unlock()
	if resp.Body != nil && resp.Body != http.NoBody {
		var raw []byte
		complete := false
		// complete: read to EOF, the connection goes back to the pool; otherwise it
		// is closed (the client would only drain 2 KiB of it anyway)
		if resp.ContentLength <= historyBodyLimit {
			raw, complete = c.captureRedirectBody(resp.Body)
		} else { // declared larger: not read at all
			_ = resp.Body.Close()
		}
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		if complete {
			rec.body = raw
			if enc := resp.Header.Get("Content-Encoding"); enc != "" && !resp.Uncompressed {
				dec := http.DecompressBodyByType(io.NopCloser(bytes.NewReader(raw)), enc)
				decoded, derr := io.ReadAll(io.LimitReader(dec, historyBodyLimit+1))
				_ = dec.Close()
				switch {
				case derr != nil: // undecodable: keep the bytes as received
				case len(decoded) > historyBodyLimit:
					rec.body = nil
				default:
					rec.body = decoded
				}
			}
		}
	} else {
		rec.body = []byte{}
	}
	c.mu.Lock()
	c.history = append(c.history, rec)
	c.mu.Unlock()
}

// captureRedirectBody reads body up to historyBodyLimit within the stall and capture
// limits, then closes it; complete=false means larger, paused, too slow or failed.
// A limit closes the transport body, also under a decompressor (closing a zstd
// decoder during its Read blocks), and only once (HTTP/2 would reset the stream again
// on the final Close).
func (c *reqControl) captureRedirectBody(body io.ReadCloser) (raw []byte, complete bool) {
	var transport *onceCloser
	if !http.ReplaceCompressedBody(body, func(b io.ReadCloser) io.ReadCloser {
		transport = &onceCloser{ReadCloser: b}
		return transport
	}) {
		transport = &onceCloser{ReadCloser: body}
		body = transport
	}
	defer func() { _ = body.Close() }() // a decompressor closes transport through it
	pause := historyStallLimit
	if c.read > 0 && c.read < pause {
		pause = c.read
	}
	abort := func() { _ = transport.Close() } // ends a pending Read
	stall := time.AfterFunc(pause, abort)
	defer stall.Stop()
	slow := time.AfterFunc(historyCaptureLimit, abort)
	defer slow.Stop()
	buf := make([]byte, 0, 4<<10)
	chunk := make([]byte, 16<<10)
	for {
		n, err := body.Read(chunk)
		buf = append(buf, chunk[:n]...)
		switch {
		case len(buf) > historyBodyLimit:
			return nil, false
		case err == io.EOF:
			return buf, true
		case err != nil:
			return nil, false
		}
		if !stall.Stop() { // fired while this read returned data
			return nil, false
		}
		stall.Reset(pause)
	}
}

// onceCloser: Close runs the underlying Close once (the others wait for it).
type onceCloser struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (o *onceCloser) Close() error {
	o.once.Do(func() { o.err = o.ReadCloser.Close() })
	return o.err
}

// historyPayload: the recorded redirects before final (oldest first).
func (c *reqControl) historyPayload(final *http.Response) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []map[string]any{}
	for _, rec := range c.history {
		if rec.resp == final {
			continue
		}
		item := map[string]any{"status": rec.status, "url": rec.url, "method": rec.method,
			"usedProtocol": rec.proto, "headers": rec.header, "cookies": rec.cookies, "elapsed": rec.elapsed}
		if rec.body != nil {
			item["body"] = base64.StdEncoding.EncodeToString(rec.body)
		} else {
			item["body"] = nil
		}
		out = append(out, item)
	}
	return out
}

// installRequestControl: deadlines move from http.Client.Timeout (fixed at
// session creation, so a per-request timeout was silently ignored) to the
// request context, and the hop hook goes in front of the transport.
func installRequestControl(client tls_client.HttpClient) error {
	v := reflect.ValueOf(client)
	if v.Kind() != reflect.Ptr || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return errors.New("unexpected tls-client client type")
	}
	c := v.Elem().FieldByName("Client")
	if !c.IsValid() || c.Type() != reflect.TypeOf((*http.Client)(nil)).Elem() {
		return errors.New("tls-client: embedded http.Client not found")
	}
	timeout := c.FieldByName("Timeout")
	if !timeout.IsValid() || !timeout.CanSet() {
		return errors.New("tls-client: http.Client.Timeout is not settable")
	}
	timeout.SetInt(0)
	jar := c.FieldByName("Jar")
	if !jar.IsValid() || !jar.CanSet() {
		return errors.New("tls-client: http.Client.Jar is not settable")
	}
	jar.Set(reflect.Zero(jar.Type())) // cookies: per-request jar in hopTransport
	return swapTransport(client, func(rt http.RoundTripper) http.RoundTripper { return &hopTransport{inner: rt} })
}

// closeClient closes a session's connections: CloseIdleConnections, then the full
// close of the transports underneath (HTTP/3 transports kept their UDP sockets and
// goroutines through CloseIdleConnections).
// Requests still running on the session (a session is also removed after one of
// its requests failed) finish first: the full close waits for them.
// after runs once the client is closed.
func closeClient(client tls_client.HttpClient, after func()) {
	client.CloseIdleConnections()
	tr := clientTransport(client)
	closer, ok := tr.(interface{ Close() })
	if !ok {
		after()
		return
	}
	if hop, isHop := tr.(*hopTransport); isHop {
		hop.use.whenIdle(func() {
			client.CloseIdleConnections()
			closer.Close()
			after()
		})
		return
	}
	closer.Close()
	after()
}

// clientTransport returns the Transport of the http.Client inside a tls-client
// HttpClient (nil when there is none).
func clientTransport(client tls_client.HttpClient) http.RoundTripper {
	v := reflect.ValueOf(client)
	if v.Kind() != reflect.Ptr || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return nil
	}
	c := v.Elem().FieldByName("Client")
	if !c.IsValid() || c.Type() != reflect.TypeOf((*http.Client)(nil)).Elem() {
		return nil
	}
	tr, _ := c.FieldByName("Transport").Interface().(http.RoundTripper)
	return tr
}

// holdSession counts the request as using its session from now until ctl.finish
// (its body read or its stream closed): the session's transports stay open for
// all of its hops, also between redirects, when no response is open. False when
// the session was removed (and is closing) after the client was looked up.
func holdSession(client tls_client.HttpClient, ctl *reqControl) bool {
	hop, ok := clientTransport(client).(*hopTransport)
	if !ok {
		return true
	}
	if !hop.use.acquire() {
		return false
	}
	ctl.mu.Lock()
	ctl.release = hop.use.end
	ctl.mu.Unlock()
	return true
}

// dialWithContext returns as soon as ctx is done even when the inner dialer
// ignores it (a late connection is closed).
func dialWithContext(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	if ctx.Done() == nil {
		return dial(ctx)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dial(ctx)
		ch <- result{conn, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// ---------------------------------------------------------------------------
// body reader: idle read timeout + size limit + error tagging
// ---------------------------------------------------------------------------

type controlledBody struct {
	io.ReadCloser
	ctl   *reqControl
	limit int64
	n     int64
}

func (b *controlledBody) Read(p []byte) (int, error) {
	b.ctl.mu.Lock()
	b.ctl.armLocked("body", b.ctl.read)
	b.ctl.mu.Unlock()
	n, err := b.ReadCloser.Read(p)
	b.ctl.mu.Lock()
	b.ctl.armLocked("body", 0)
	if errors.Is(err, io.EOF) && b.ctl.bodyDone.IsZero() {
		b.ctl.bodyDone = time.Now()
	}
	b.ctl.mu.Unlock()
	b.n += int64(n)
	if b.limit > 0 && b.n > b.limit {
		err = &bodyTooLarge{limit: b.limit}
		b.ctl.cancel(err)
		return n, err
	}
	if err != nil && !errors.Is(err, io.EOF) {
		if cause := context.Cause(b.ctl.ctx); cause != nil {
			return n, cause
		}
	}
	return n, err
}

// ---------------------------------------------------------------------------
// error classification
// ---------------------------------------------------------------------------

func errorPayload(err error, ctl *reqControl) map[string]any {
	kind, stage := classifyError(err, ctl)
	msg := err.Error()
	if ctl != nil {
		if cause := context.Cause(ctl.ctx); cause != nil && kind != "request" {
			var st *stageTimeout
			var pm *protocolMismatch
			if errors.As(cause, &st) || errors.Is(cause, errCancelled) || errors.As(cause, &pm) {
				msg = cause.Error()
			}
		}
	}
	out := map[string]any{"status": 0, "body": msg, "errorKind": kind, "errorStage": stage}
	if ctl != nil {
		out["requestId"] = ctl.id
		out["elapsed"] = time.Since(ctl.start).Seconds()
	}
	return out
}

func classifyError(err error, ctl *reqControl) (kind, stage string) {
	stage = "request"
	if ctl != nil {
		stage = ctl.currentStage()
		if stage == "headers" {
			stage = "read"
		}
		cause := context.Cause(ctl.ctx)
		var st *stageTimeout
		var big *bodyTooLarge
		var pm *protocolMismatch
		switch {
		case errors.As(cause, &pm):
			return "protocol", "connect"
		case errors.As(cause, &st):
			if st.stage == "total" {
				return "timeout", stage
			}
			return st.kind(), st.stage
		case errors.Is(cause, errCancelled):
			return "cancelled", stage
		case errors.Is(cause, errStreamClosed):
			return "stream_closed", stage
		case errors.As(cause, &big):
			return "body_too_large", "body"
		}
	}
	var big *bodyTooLarge
	if errors.As(err, &big) {
		return "body_too_large", "body"
	}
	var headerErr *http2.RequestHeaderError
	if errors.As(err, &headerErr) {
		return "invalid_request", "request"
	}
	var refused *alpnRefusedError
	if errors.As(err, &refused) {
		return "protocol", "connect"
	}
	var pe *proxyDialError
	if errors.As(err, &pe) {
		if isTimeout(pe.err) {
			return "connect_timeout", "connect"
		}
		return "proxy", "connect"
	}
	if isTimeout(err) {
		if stage == "connect" {
			return "connect_timeout", stage
		}
		if stage == "write" {
			return "write_timeout", stage
		}
		return "read_timeout", stage
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns", "connect"
	}
	if isTLSError(err) || strings.Contains(strings.ToLower(err.Error()), "server gave http response to https client") {
		return "tls", "connect"
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "proxy") || strings.Contains(text, "socks") {
		return "proxy", "connect"
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(text, "connection refused") ||
		strings.Contains(text, "no route to host") || strings.Contains(text, "network is unreachable") ||
		strings.Contains(text, "actively refused") {
		return "connect", "connect"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, net.ErrClosed) || strings.Contains(text, "connection reset") ||
		strings.Contains(text, "broken pipe") || strings.Contains(text, "server closed") ||
		strings.Contains(text, "forcibly closed") || strings.Contains(text, "goaway") ||
		strings.Contains(text, "unexpected eof") || strings.HasSuffix(text, ": eof") || text == "eof" {
		if stage == "connect" {
			return "connect", stage
		}
		return "connection_closed", stage
	}
	if stage == "connect" {
		return "connect", stage
	}
	return "request", stage
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

func isTLSError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var alert tls.AlertError
	var record tls.RecordHeaderError
	var verify *tls.CertificateVerificationError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid) ||
		errors.As(err, &alert) || errors.As(err, &record) || errors.As(err, &verify) {
		return true
	}
	text := err.Error()
	return strings.Contains(text, "tls:") || strings.Contains(text, "x509:") || strings.Contains(text, "certificate")
}
