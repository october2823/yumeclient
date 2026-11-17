package main

// okhttp4 HTTP layer (0.4.7).
//
// header_style="okhttp": every request a session sends (redirect hops too)
// passes okhttpBridge, which rebuilds the header block the way okhttp 4.x
// BridgeInterceptor + Http1ExchangeCodec put it on the wire:
//
//	<application headers: names as given, in insertion order>
//	Content-Type: ...           requests with a body; value from the application
//	Content-Length: N           computed by the transport (Transfer-Encoding: chunked otherwise)
//	Host: host[:port]           port only when it is not the scheme default
//	Connection: Keep-Alive
//	Accept-Encoding: gzip       unless the application set Accept-Encoding or Range
//	Cookie: a=b; c=d            session cookie jar
//	User-Agent: okhttp/4.12.0   unless the application set one
//
// Host / Connection / Accept-Encoding / User-Agent set by the application stay
// where the application put them: okhttp only fills in missing ones. On HTTP/2
// the same order applies; Host becomes :authority and Connection is dropped by
// the h2 encoder, as in okhttp's Http2ExchangeCodec.
//
// keep_alpn (strictH1Transport): HTTP/1.1 on connections whose ClientHello
// keeps the profile's ALPN offer ("h2","http/1.1"). The server picks the
// protocol (RFC 7301); if it picks h2 the connection is closed right after the
// handshake, before a single HTTP byte, and the request fails.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/httptrace"
	tls_client "github.com/bogdanfinn/tls-client"
	tls "github.com/bogdanfinn/utls"
	"golang.org/x/net/idna"
	proxy "golang.org/x/net/proxy"
)

const (
	okhttpUserAgent = "okhttp/4.12.0"
	// okhttp ConnectionPool defaults: 5 idle connections, 5 minutes keep-alive
	okhttpKeepAlive = 5 * time.Minute
	okhttpMaxIdle   = 5
)

// sessionExtras: session-level fields of the payload that upstream RequestInput
// does not know.
type sessionExtras struct {
	HeaderStyle string `json:"headerStyle"`
	KeepAlpn    bool   `json:"keepAlpn"`
}

func decodeSessionExtras(rawPayload []byte) sessionExtras {
	var e sessionExtras
	_ = json.Unmarshal(rawPayload, &e)
	return e
}

func (e sessionExtras) okhttp() bool { return e.HeaderStyle == "okhttp" }

func okhttpTransportOptions() *tls_client.TransportOptions {
	idle := okhttpKeepAlive
	// 8 KiB write buffer = one Okio segment: a request up to 8 KiB leaves in one write
	return &tls_client.TransportOptions{IdleConnTimeout: &idle, MaxIdleConns: okhttpMaxIdle, MaxIdleConnsPerHost: okhttpMaxIdle,
		WriteBufferSize: 8192}
}

// sessionStyles: client -> true for header_style="okhttp" sessions (the
// plain-http path in schemeGuard needs to know)
var sessionStyles sync.Map

func isOkhttpSession(client tls_client.HttpClient) bool {
	v, ok := sessionStyles.Load(client)
	return ok && v.(bool)
}

// ---------------------------------------------------------------------------
// BridgeInterceptor
// ---------------------------------------------------------------------------

type okhttpBridge struct {
	inner http.RoundTripper
	jar   http.CookieJar // the session jar: tells jar cookies from application ones
}

func (b *okhttpBridge) RoundTrip(req *http.Request) (*http.Response, error) {
	// hook composed in front of the caller's trace (the reporter's)
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if !info.Reused {
				disableDynamicRecordSizing(info.Conn)
			}
		},
	})
	r := req.Clone(ctx) // RoundTrippers must not modify the caller's request
	okhttpLayout(r, b.jar)
	singleWriteBody(req, r)
	return b.inner.RoundTrip(r)
}

// io.nopCloser (the non-WriterTo variant) is the wrapper fhttp's
// isKnownInMemoryReader unwraps; Go >= 1.20 io.NopCloser(*bytes.Buffer) returns
// nopCloserWriterTo, which fhttp does not know, so it flushes the request head
// before every body: two writes, two TLS records. okhttp (Okio) buffers head and
// body and flushes once in finishRequest.
var nopCloserT = reflect.TypeOf(io.NopCloser(struct{ io.Reader }{}))

var nopCloserUsable = nopCloserT.Kind() == reflect.Struct && nopCloserT.NumField() == 1 &&
	nopCloserT.Field(0).Type == reflect.TypeOf((*io.Reader)(nil)).Elem() && nopCloserT.Field(0).IsExported()

func inMemoryBody(b []byte) io.ReadCloser {
	v := reflect.New(nopCloserT).Elem()
	v.Field(0).Set(reflect.ValueOf(bytes.NewReader(b)))
	return v.Interface().(io.ReadCloser)
}

// singleWriteBody swaps an in-memory request body (all yumeclient bodies are)
// for the wrapper fhttp recognizes, so head and body leave in one write.
func singleWriteBody(orig, r *http.Request) {
	if !nopCloserUsable || r.Body == nil || r.Body == http.NoBody || r.ContentLength <= 0 || r.ContentLength > 8<<20 {
		return
	}
	var b []byte
	if r.GetBody != nil {
		rc, err := r.GetBody()
		if err != nil {
			return
		}
		b, err = io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || int64(len(b)) != r.ContentLength {
			return
		}
		_ = orig.Body.Close() // replaced: the inner transport closes r.Body only
	} else {
		// redirect hops (307/308) carry a fresh body without GetBody
		var err error
		b, err = io.ReadAll(io.LimitReader(r.Body, r.ContentLength+1))
		_ = r.Body.Close()
		if err != nil || int64(len(b)) != r.ContentLength {
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), errReader{err}))
			return
		}
	}
	r.Body = inMemoryBody(b)
	r.GetBody = func() (io.ReadCloser, error) { return inMemoryBody(b), nil }
}

// errReader re-surfaces a body read error to the transport
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) {
	if e.err == nil {
		return 0, io.EOF
	}
	return 0, e.err
}

// disableDynamicRecordSizing: BoringSSL (Conscrypt) writes application data in
// records of up to 16 KiB; Go/utls open a connection with ~1.2 KiB records and
// grow them (dynamic record sizing), so a request head over ~1.2 KiB would leave
// as several records instead of one. tls-client builds a fresh tls.Config per
// dial and offers no knob, so the flag is set on that connection's own config
// when the connection is first handed to a request (before its first byte on
// HTTP/1.1; on HTTP/2 only the connection preface precedes it).
func disableDynamicRecordSizing(c net.Conn) {
	uc, ok := c.(*tls.UConn)
	if !ok || uc == nil || uc.Conn == nil {
		return
	}
	f := reflect.ValueOf(uc.Conn).Elem().FieldByName("config")
	if !f.IsValid() || f.Type() != reflect.TypeOf((*tls.Config)(nil)) || f.IsNil() {
		return
	}
	(*tls.Config)(unsafe.Pointer(f.Pointer())).DynamicRecordSizingDisabled = true
}

func (b *okhttpBridge) CloseIdleConnections() {
	if c, ok := b.inner.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// methods okhttp sends with a request body (HttpMethod.requiresRequestBody)
var okhttpBodyMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "PROPPATCH": true, "REPORT": true}

// BridgeInterceptor slots after the application headers, in its order
var okhttpTail = []string{"content-type", "content-length", "transfer-encoding", "host", "connection", "accept-encoding", "cookie", "user-agent"}

func foldKeys(h http.Header, name string) []string {
	var keys []string
	for k := range h {
		if k == http.HeaderOrderKey || k == http.PHeaderOrderKey {
			continue
		}
		if strings.EqualFold(k, name) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// okhttpHostHeader = HttpUrl.toHostHeader(): lowercase ASCII host, IPv6 in
// brackets, ":port" only when not the scheme default. An explicit Host override
// (requestHostOverride) wins.
func okhttpHostHeader(r *http.Request) string {
	if r.URL == nil {
		return r.Host
	}
	if r.Host != "" && r.Host != r.URL.Host {
		return r.Host
	}
	host := strings.ToLower(r.URL.Hostname())
	if a, err := idna.Lookup.ToASCII(host); err == nil && a != "" {
		host = a
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	def := "443"
	if strings.EqualFold(r.URL.Scheme, "http") {
		def = "80"
	}
	if port := r.URL.Port(); port != "" && port != def {
		host += ":" + port
	}
	return host
}

func okhttpLayout(r *http.Request, jar http.CookieJar) {
	h := r.Header
	if h == nil {
		h = http.Header{}
		r.Header = h
	}
	appOrder := h[http.HeaderOrderKey] // lowercased by tls-client
	delete(h, http.HeaderOrderKey)
	hop := r.Response != nil // redirect follow-up built by http.Client
	hasBody := (r.Body != nil && r.Body != http.NoBody) || okhttpBodyMethods[strings.ToUpper(r.Method)]

	has := func(name string) bool { return len(foldKeys(h, name)) > 0 }
	take := func(name string) (string, bool) {
		val, ok := "", false
		for _, k := range foldKeys(h, name) {
			if !ok && len(h[k]) > 0 {
				val, ok = h[k][0], true
			}
			delete(h, k)
		}
		return val, ok
	}
	listed := map[string]bool{}
	for _, n := range appOrder {
		listed[strings.ToLower(n)] = true
	}

	// body headers: BridgeInterceptor re-sets Content-Type from the body and
	// Content-Length/Transfer-Encoding from its length (the transport writes those)
	contentType, haveCT := "", false
	if hasBody {
		contentType, haveCT = take("content-type")
		take("content-length")
		take("transfer-encoding")
	} else if hop {
		// a redirect that became a GET: okhttp drops the body headers
		take("content-type")
		take("content-length")
		take("transfer-encoding")
	}
	if hop && !listed["referer"] {
		take("referer") // fhttp adds Referer on redirect hops; okhttp never does
	}

	// cookies: http.Client merged the jar into "Cookie". okhttp sets one Cookie
	// header from the jar after Accept-Encoding; an application cookie header
	// under another spelling is kept in front of the jar cookies.
	cookie := ""
	if jar != nil && r.URL != nil && len(jar.Cookies(r.URL)) > 0 {
		var parts []string
		keys := foldKeys(h, "cookie")
		for _, k := range keys {
			if k != "Cookie" {
				parts = append(parts, h[k]...)
			}
		}
		parts = append(parts, h["Cookie"]...)
		for _, k := range keys {
			delete(h, k)
		}
		kept := parts[:0]
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				kept = append(kept, p)
			}
		}
		cookie = strings.Join(kept, "; ")
	}

	// order: application headers as listed, then BridgeInterceptor's slots
	order := make([]string, 0, len(h)+len(okhttpTail))
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			order = append(order, n)
		}
	}
	present := map[string]bool{}
	for k := range h {
		if k != http.PHeaderOrderKey {
			present[strings.ToLower(k)] = true
		}
	}
	for _, n := range appOrder {
		if n = strings.ToLower(n); present[n] {
			add(n)
		}
	}
	var unlisted []string
	for n := range present {
		if !seen[n] {
			unlisted = append(unlisted, n)
		}
	}
	sort.Strings(unlisted)
	for _, n := range unlisted {
		add(n)
	}
	for _, n := range okhttpTail {
		add(n)
	}

	if haveCT {
		h["Content-Type"] = []string{contentType}
	}
	if keys := foldKeys(h, "host"); len(keys) > 0 && len(h[keys[0]]) > 0 {
		r.Host = h[keys[0]][0] // application Host header: stays in place, also :authority
	} else {
		r.Host = okhttpHostHeader(r)
		h["Host"] = []string{r.Host}
	}
	if !has("connection") {
		h["Connection"] = []string{"Keep-Alive"}
	}
	if !has("accept-encoding") && !has("range") {
		h["Accept-Encoding"] = []string{"gzip"}
	}
	if cookie != "" {
		h["Cookie"] = []string{cookie}
	}
	if !has("user-agent") {
		h["User-Agent"] = []string{okhttpUserAgent}
	}
	h[http.HeaderOrderKey] = order
}

// ---------------------------------------------------------------------------
// strict HTTP/1.1 with the profile's ALPN offer (keep_alpn)
// ---------------------------------------------------------------------------

type alpnRefusedError struct{ addr, proto string }

func (e *alpnRefusedError) Error() string {
	return fmt.Sprintf("keep_alpn: server %s selected ALPN %q, HTTP/1.1 is not possible on this connection "+
		"(the ClientHello offered the profile's ALPN list; the server chooses, RFC 7301). The connection was "+
		"closed right after the handshake, nothing was sent. http_version='auto' follows the server like okhttp; "+
		"without keep_alpn the hello offers http/1.1 only", e.addr, e.proto)
}

type strictH1Config struct {
	dialer       proxy.ContextDialer
	helloID      tls.ClientHelloID
	shuffle      bool
	disableHttp3 bool
	insecure     bool
	serverName   string
	noTickets    bool
}

// helloResumes mirrors tls-client: a session cache only for specs that carry
// pre_shared_key (TLS 1.3 resumption)
func helloResumes(id tls.ClientHelloID) bool {
	spec, err := id.ToSpec()
	if err != nil {
		if spec, err = tls.UTLSIdToSpec(id); err != nil {
			return false
		}
	}
	for _, e := range spec.Extensions {
		if _, ok := e.(*tls.UtlsPreSharedKeyExtension); ok {
			return true
		}
	}
	return false
}

func newStrictH1Transport(cfg *strictH1Config, opts *tls_client.TransportOptions) *http.Transport {
	var cache tls.ClientSessionCache
	if !cfg.noTickets && helloResumes(cfg.helloID) {
		cache = tls.NewLRUClientSessionCache(32)
	}
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := cfg.dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host := cfg.serverName
		if host == "" {
			if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
				host = h
			} else {
				host = addr
			}
		}
		tlsCfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: cfg.insecure,
			ClientSessionCache: cache,
			OmitEmptyPsk:       true,
			// BoringSSL (Conscrypt) fills records up to 16 KiB; Go's adaptive
			// sizing would cut a request head over ~1.2 KiB into several records
			DynamicRecordSizingDisabled: true,
		}
		uc := tls.UClient(raw, tlsCfg, cfg.helloID, cfg.shuffle, false, cfg.disableHttp3)
		if err := uc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		if p := uc.ConnectionState().NegotiatedProtocol; p != "" && p != "http/1.1" && p != "http/1.0" {
			_ = uc.Close()
			return nil, &alpnRefusedError{addr: addr, proto: p}
		}
		return uc, nil
	}
	t := &http.Transport{
		DialContext:     cfg.dialer.DialContext,
		DialTLSContext:  dialTLS,
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{}, // never upgrade to h2
		IdleConnTimeout: 90 * time.Second,                                       // tls-client default
	}
	if opts != nil {
		if opts.IdleConnTimeout != nil {
			t.IdleConnTimeout = *opts.IdleConnTimeout
		}
		t.MaxIdleConns = opts.MaxIdleConns
		t.MaxIdleConnsPerHost = opts.MaxIdleConnsPerHost
		t.WriteBufferSize = opts.WriteBufferSize
	}
	return t
}

// ---------------------------------------------------------------------------
// session assembly
// ---------------------------------------------------------------------------

// swapTransport replaces the RoundTripper of the http.Client embedded in a
// tls-client HttpClient (upstream exposes no option to wrap its transport).
func swapTransport(client tls_client.HttpClient, wrap func(http.RoundTripper) http.RoundTripper) error {
	v := reflect.ValueOf(client)
	if v.Kind() != reflect.Ptr || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return errors.New("unexpected tls-client client type")
	}
	c := v.Elem().FieldByName("Client")
	if !c.IsValid() || c.Type() != reflect.TypeOf((*http.Client)(nil)).Elem() {
		return errors.New("tls-client: embedded http.Client not found")
	}
	tr := c.FieldByName("Transport")
	if !tr.IsValid() || !tr.CanSet() {
		return errors.New("tls-client: http.Client.Transport is not settable")
	}
	cur, _ := tr.Interface().(http.RoundTripper)
	next := wrap(cur)
	tr.Set(reflect.ValueOf(&next).Elem())
	return nil
}

// applySessionLayer installs the strict HTTP/1.1 transport (keep_alpn) and the
// okhttp bridge on a freshly built client.
func applySessionLayer(client tls_client.HttpClient, okhttp bool, strict *strictH1Config) error {
	if strict != nil {
		var opts *tls_client.TransportOptions
		if okhttp {
			opts = okhttpTransportOptions()
		}
		t := newStrictH1Transport(strict, opts)
		if err := swapTransport(client, func(http.RoundTripper) http.RoundTripper { return t }); err != nil {
			return err
		}
	}
	if okhttp {
		jar := client.GetCookieJar()
		if err := swapTransport(client, func(rt http.RoundTripper) http.RoundTripper { return &okhttpBridge{inner: rt, jar: jar} }); err != nil {
			return err
		}
	}
	sessionStyles.Store(client, okhttp)
	return nil
}
