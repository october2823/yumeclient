package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/httptrace"
	tls_client "github.com/bogdanfinn/tls-client"
	src "github.com/bogdanfinn/tls-client/cffi_src"
)

func jsonOut(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		return C.CString(`{"status":0,"body":"response encoding failed","errorKind":"request"}`)
	}
	return C.CString(string(b))
}

func failure(kind, msg string, ctl *reqControl) map[string]any {
	out := map[string]any{"status": 0, "body": msg, "errorKind": kind, "errorStage": "request"}
	if ctl != nil {
		out["requestId"] = ctl.id
	}
	return out
}

//export yumeclient_call
func yumeclient_call(input *C.char) *C.char {
	return jsonOut(runCall([]byte(C.GoString(input))))
}

func runCall(rawInput []byte) map[string]any {
	var in src.RequestInput
	if err := json.Unmarshal(rawInput, &in); err != nil {
		return failure("invalid_request", "invalid input: "+err.Error(), nil)
	}
	opts := decodeRequestOptions(rawInput)
	ctl := newReqControl(opts.RequestId, opts, in.WithProtocolRacing)
	if !registerRequest(ctl) { // cancelled before the call started
		ctl.cancel(errCancelled)
		out := errorPayload(errCancelled, ctl)
		ctl.finish()
		return out
	}
	streamed := false
	defer func() {
		if !streamed {
			unregisterRequest(ctl)
			ctl.finish()
		}
	}()

	sessionProxy := ""
	if in.ProxyUrl != nil {
		sessionProxy = *in.ProxyUrl
	}
	client, session, withSession, clientErr := createPatchedClient(in, rawInput)
	if clientErr != nil {
		return failure("configuration", "client creation failed: "+clientErr.Error(), ctl)
	}
	req, clientErr := src.BuildRequest(in)
	if clientErr != nil {
		return failure("invalid_request", clientErr.Error(), ctl)
	}
	// cookies: a fresh RFC 6265 jar per call, seeded from the Python jar; explicit
	// per-request cookies (requestCookies) override same-name jar cookies for this URL
	ctl.jar = newRequestJar()
	ctl.jar.seed(opts.Jar)
	if len(in.RequestCookies) > 0 && req.URL != nil {
		pairs := map[string]string{}
		for _, c := range in.RequestCookies {
			if c.Name != "" {
				pairs[c.Name] = c.Value
			}
		}
		ctl.jar.override(req.URL, pairs)
	}
	trace := &connTrace{}
	ctx := httptrace.WithClientTrace(ctl.ctx, trace.clientTrace())
	ctx = httptrace.WithClientTrace(ctx, ctl.trace())
	req = req.WithContext(withControl(ctx, ctl))
	resp, err := wrapClient(client, sessionProxy).Do(req)
	if err != nil {
		out := errorPayload(err, ctl)
		// a broken session is rebuilt on the next call; a cancelled or timed-out
		// request leaves the pool usable (the transport already dropped the conn)
		if withSession && !isControlCause(ctl) {
			src.RemoveSession(session)
			removePatchedSession(session)
		}
		return out
	}
	ctl.headersDone(opts.Stream)
	resp.Body = &controlledBody{ReadCloser: resp.Body, ctl: ctl}
	body := resp.Body
	if !resp.Uncompressed {
		body = http.DecompressBodyByType(resp.Body, resp.Header.Get("Content-Encoding"))
	}
	if opts.MaxBodyBytes > 0 {
		// counted after decompression: a small gzip body must not expand past the limit
		body = &decodedLimit{ReadCloser: body, ctl: ctl, limit: opts.MaxBodyBytes}
	}

	payload := map[string]any{"status": resp.StatusCode, "headers": resp.Header, "usedProtocol": resp.Proto,
		"target": "", "requestId": ctl.id}
	if withSession {
		payload["sessionId"] = session
	}
	if resp.Request != nil && resp.Request.URL != nil {
		payload["target"] = resp.Request.URL.String()
	}

	if opts.Stream {
		finishPayload(payload, in, rawInput, client, resp, trace, ctl, true)
		id := openStream(ctl, body, resp.Body)
		payload["streamId"] = id
		streamed = true
		return payload
	}

	data, readErr := io.ReadAll(body)
	_ = body.Close()
	if readErr != nil {
		out := errorPayload(readErr, ctl)
		if withSession && !isControlCause(ctl) {
			src.RemoveSession(session)
			removePatchedSession(session)
		}
		return out
	}
	ctl.mu.Lock()
	if ctl.bodyDone.IsZero() {
		ctl.bodyDone = time.Now()
	}
	ctl.mu.Unlock()
	payload["body"] = base64.StdEncoding.EncodeToString(data)
	finishPayload(payload, in, rawInput, client, resp, trace, ctl, false)
	return payload
}

func withControl(ctx context.Context, ctl *reqControl) context.Context {
	return context.WithValue(ctx, controlKey{}, ctl)
}

// isControlCause: the request ended because of our own cancel/timeout.
func isControlCause(ctl *reqControl) bool {
	cause := context.Cause(ctl.ctx)
	if cause == nil {
		return false
	}
	var st *stageTimeout
	var big *bodyTooLarge
	return errors.Is(cause, errCancelled) || errors.As(cause, &st) || errors.As(cause, &big)
}

func finishPayload(payload map[string]any, in src.RequestInput, rawInput []byte, client tls_client.HttpClient,
	resp *http.Response, trace *connTrace, ctl *reqControl, headersOnly bool) {
	var finalURL *url.URL
	if resp.Request != nil {
		finalURL = resp.Request.URL
	}
	payload["cookies"] = ctl.jar.valuesFor(finalURL)
	payload["jarDelta"] = ctl.jar.delta()
	info := map[string]any{}
	trace.report(info, resp)
	delete(info, "request_headers")
	remote, local := ctl.addresses()
	if remote != "" {
		info["remote_address"] = remote
	}
	if local != "" {
		info["local_address"] = local
	}
	timings := ctl.timings()
	if headersOnly {
		timings["body"] = nil
	}
	info["timings"] = timings
	payload["connectionInfo"] = info
	if wantsFingerprint(rawInput) {
		var target *url.URL
		if resp.Request != nil {
			target = resp.Request.URL
		}
		fp := fingerprintForSession(in, rawInput, client, target)
		if fp == nil {
			fp = map[string]any{}
		}
		trace.report(fp, resp)
		payload["fingerprint"] = fp
	}
}

// ---------------------------------------------------------------------------
// native response streams: yumeclient_call with "stream": true returns the
// head plus a streamId; Python pulls the body with yumeclient_stream_read into
// its own buffer (no base64, bounded memory) and must call
// yumeclient_stream_close (also on early exit / GC).
// ---------------------------------------------------------------------------

var errStreamClosed = errors.New("stream closed")

type nativeStream struct {
	mu     sync.Mutex
	ctl    *reqControl
	body   io.ReadCloser // decoded body
	raw    io.ReadCloser
	eof    atomic.Bool
	closed bool
}

var streams = struct {
	sync.Mutex
	m map[string]*nativeStream
}{m: map[string]*nativeStream{}}

var streamSeq atomic.Uint64

func openStream(ctl *reqControl, body, raw io.ReadCloser) string {
	id := ctl.id
	if id == "" {
		id = "stream-" + time.Now().Format("150405.000000000") + "-" + itoa(streamSeq.Add(1))
	}
	streams.Lock()
	streams.m[id] = &nativeStream{ctl: ctl, body: body, raw: raw}
	streams.Unlock()
	return id
}

func itoa(v uint64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func lookupStream(id string) *nativeStream {
	streams.Lock()
	defer streams.Unlock()
	return streams.m[id]
}

//export yumeclient_stream_read
func yumeclient_stream_read(streamId *C.char, buf unsafe.Pointer, size C.int) *C.char {
	s := lookupStream(C.GoString(streamId))
	if s == nil {
		return jsonOut(failure("stream_closed", "stream is closed", nil))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return jsonOut(failure("stream_closed", "stream is closed", s.ctl))
	}
	if s.eof.Load() || size <= 0 {
		return jsonOut(map[string]any{"status": 1, "n": 0, "eof": s.eof.Load()})
	}
	dst := unsafe.Slice((*byte)(buf), int(size))
	n, err := 0, error(nil)
	for spins := 0; n == 0 && err == nil && spins < 100; spins++ {
		n, err = s.body.Read(dst)
	}
	if errors.Is(err, io.EOF) {
		s.eof.Store(true)
		err = nil
	}
	if err != nil {
		out := errorPayload(err, s.ctl)
		out["n"] = n
		return jsonOut(out)
	}
	return jsonOut(map[string]any{"status": 1, "n": n, "eof": s.eof.Load()})
}

func closeStream(id string) {
	streams.Lock()
	s := streams.m[id]
	delete(streams.m, id)
	streams.Unlock()
	if s == nil {
		return
	}
	if !s.eof.Load() {
		s.ctl.cancel(errStreamClosed) // unblocks a read in progress
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		_ = s.body.Close()
		_ = s.raw.Close()
	}
	s.mu.Unlock()
	unregisterRequest(s.ctl)
	s.ctl.finish()
}

//export yumeclient_stream_close
func yumeclient_stream_close(streamId *C.char) {
	closeStream(C.GoString(streamId))
}

// decodedLimit enforces max_content_size on the decoded body.
type decodedLimit struct {
	io.ReadCloser
	ctl   *reqControl
	limit int64
	n     int64
}

func (d *decodedLimit) Read(p []byte) (int, error) {
	n, err := d.ReadCloser.Read(p)
	d.n += int64(n)
	if d.n > d.limit {
		tooLarge := &bodyTooLarge{limit: d.limit}
		d.ctl.cancel(tooLarge)
		return n, tooLarge
	}
	return n, err
}
