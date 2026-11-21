package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls "github.com/bogdanfinn/utls"
)

// plainRoutes: the transports of a session's http:// requests.
//
// They used to run on a separate http.Client (schemeGuard), which followed
// redirects itself: a redirect from http:// to https:// reached the https server
// through Go's default transport - Go's own ClientHello instead of the profile's,
// system certificate checks despite verify=False. Now the session's client follows
// every redirect and hopTransport picks the transport per hop: https:// goes to
// the tls-client transport, http:// here.
//
//   - HTTP/1.1: a plain transport with the session's proxy (absolute-form requests
//     to an HTTP proxy, like any client) and local address
//   - HTTP/2 with prior knowledge (h2c) for http_version="2": the tls-client round
//     tripper's HTTP/2 fingerprint over its dialer (third_party tls-client h2c.go)
type plainRoutes struct {
	proxyUrl    string
	localAddr   *net.TCPAddr
	dialTimeout time.Duration
	okhttp      bool
	jar         http.CookieJar
	h2cOf       func() http.RoundTripper // nil: the session cannot speak h2c
	// dial: the session's own dialer (proxy, local address); SOCKS proxies go
	// through it (the plain transport would send socks5h:// / socks4:// requests
	// to the proxy as plaintext HTTP-proxy requests)
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	mu sync.Mutex
	t1 *http.Transport
	h1 http.RoundTripper
}

type plainConfig struct {
	proxyUrl  string
	localAddr *net.TCPAddr
	// dialTimeout: the session's limit on opening a connection (timeoutMilliseconds);
	// a fixed 30 s before 0.8.2
	dialTimeout time.Duration
}

func newPlainRoutes(client interface{ GetCookieJar() http.CookieJar }, cfg plainConfig, okhttp bool, inner http.RoundTripper) *plainRoutes {
	p := &plainRoutes{proxyUrl: cfg.proxyUrl, localAddr: cfg.localAddr, dialTimeout: cfg.dialTimeout, okhttp: okhttp, jar: client.GetCookieJar()}
	if p.dialTimeout <= 0 {
		p.dialTimeout = 30 * time.Second
	}
	if h, ok := unwrapBridge(inner).(interface{ H2C() http.RoundTripper }); ok {
		p.h2cOf = h.H2C
	}
	if d, ok := unwrapBridge(inner).(interface {
		DialPlain(ctx context.Context, network, addr string) (net.Conn, error)
	}); ok {
		p.dial = d.DialPlain
	}
	return p
}

// unwrapBridge: the transport under the okhttp bridge, if any.
func unwrapBridge(rt http.RoundTripper) http.RoundTripper {
	if b, ok := rt.(*okhttpBridge); ok {
		return b.inner
	}
	return rt
}

// errNoH2C: the session's transport cannot speak h2c (keep_alpn sessions).
type errNoH2C struct{}

func (errNoH2C) Error() string { return "HTTP/2 over cleartext is not available for this session" }

func (p *plainRoutes) transport(h2c bool) (http.RoundTripper, error) {
	if h2c {
		if p.h2cOf == nil {
			return nil, errNoH2C{}
		}
		rt := p.h2cOf()
		if p.okhttp {
			rt = &okhttpBridge{inner: rt, jar: p.jar}
		}
		return rt, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h1 == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		// the session's proxy only: the https:// transport does not read
		// HTTP_PROXY / HTTPS_PROXY from the environment either
		t.Proxy = proxyFuncFromUrl(p.proxyUrl)
		// the TLS leg to an https:// proxy is not certificate-verified, as for https://
		// requests (newInsecureHttpsConnectDialer); before 0.8.1 http:// requests through
		// an https:// proxy verified it and failed where https:// ones worked
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		d := &net.Dialer{Timeout: p.dialTimeout, KeepAlive: 30 * time.Second}
		if p.localAddr != nil {
			d.LocalAddr = p.localAddr
		}
		t.DialContext = d.DialContext
		if strings.HasPrefix(strings.ToLower(p.proxyUrl), "socks") && p.dial != nil {
			t.Proxy, t.DialContext = nil, p.dial
		}
		if p.okhttp {
			t.IdleConnTimeout, t.MaxIdleConns, t.MaxIdleConnsPerHost = okhttpKeepAlive, okhttpMaxIdle, okhttpMaxIdle
		}
		p.t1, p.h1 = t, t
		if p.okhttp {
			p.h1 = &okhttpBridge{inner: t, jar: p.jar}
		}
	}
	return p.h1, nil
}

// closeIdle closes the idle HTTP/1.1 connections (h2c ones close with the
// tls-client round tripper).
func (p *plainRoutes) closeIdle() {
	p.mu.Lock()
	t := p.t1
	p.mu.Unlock()
	if t != nil {
		t.CloseIdleConnections()
	}
}
