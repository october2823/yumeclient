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
	"context"
	"crypto/x509"
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
	"github.com/bogdanfinn/fhttp/httptrace"
	tls_client "github.com/bogdanfinn/tls-client"
	tls "github.com/bogdanfinn/utls"
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
}

func decodeRequestOptions(raw []byte) requestOptions {
	var o requestOptions
	_ = json.Unmarshal(raw, &o)
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

	connect, write, read, total time.Duration
	// stageTimers=false for protocol-racing sessions: quic-go's HTTP/3 transport
	// does not report fhttp trace events, so connect/write timers could fire on
	// a healthy h3 exchange. Total and body-read timeouts still apply.
	stageTimers bool
	// jar: per-request cookie jar consulted by hopTransport on every hop
	jar *requestJar

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
	remote, local                                                string
}

func newReqControl(id string, opts requestOptions, racing bool) *reqControl {
	ctx, cancel := context.WithCancelCause(context.Background())
	c := &reqControl{id: id, ctx: ctx, cancel: cancel, stageTimers: !racing,
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
	c.mu.Unlock()
	c.cancel(nil) // release the context; a nil cause after completion is a no-op for callers
}

func (c *reqControl) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if c.dialing.Load() > 0 {
				return
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			c.gotConn = time.Now()
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
	c.remote, c.local = "", ""
	if c.stageTimers {
		c.armLocked("connect", c.connect)
	} else {
		c.armLocked("connect", 0)
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
type hopTransport struct{ inner http.RoundTripper }

func (h *hopTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c := controlFrom(req.Context())
	if c != nil {
		c.hopBegin()
		// cookie handling moved here from http.Client.Jar (which is nil now): same
		// AddCookie / SetCookies steps the client performs, but on the per-request jar
		if c.jar != nil {
			if cookies := c.jar.Cookies(req.URL); len(cookies) > 0 {
				req = req.Clone(req.Context())
				for _, ck := range cookies {
					req.AddCookie(ck)
				}
			}
		}
	}
	resp, err := h.inner.RoundTrip(req)
	if c != nil && err == nil {
		c.hopReturned()
		if c.jar != nil {
			if rc := resp.Cookies(); len(rc) > 0 {
				c.jar.SetCookies(req.URL, rc)
			}
		}
	}
	return resp, err
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
			if errors.As(cause, &st) || errors.Is(cause, errCancelled) {
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
		switch {
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
