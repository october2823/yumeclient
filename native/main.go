package main

/*
#include <stdlib.h>
*/
import "C"

import (
 "bufio"
 "context"
 "crypto/tls"
 "encoding/base64"
 "encoding/json"
 "fmt"
 "net"
 "net/url"
 "strings"
 "sync"
 "time"
 "unsafe"

 http "github.com/bogdanfinn/fhttp"
 "github.com/bogdanfinn/tls-client/profiles"
 src "github.com/bogdanfinn/tls-client/cffi_src"
 tls_client "github.com/bogdanfinn/tls-client"
 proxy "golang.org/x/net/proxy"
)

// cookiePair mirrors a single cookie with its attributes for the Python side.
type cookiePair struct {
 Name     string `json:"name"`
 Value    string `json:"value"`
 Domain   string `json:"domain"`
 Path     string `json:"path,omitempty"`
 Expires  int64  `json:"expires,omitempty"`
 Secure   bool   `json:"secure,omitempty"`
 HttpOnly bool   `json:"httpOnly,omitempty"`
}

func unixOrZero(t time.Time) int64 {
 if t.IsZero() { return 0 }
 return t.Unix()
}

func pairsFrom(cookies []*http.Cookie, domain string) []cookiePair {
 pairs := make([]cookiePair, 0, len(cookies))
 for _, c := range cookies {
  if c == nil || c.Name == "" { continue }
  pairs = append(pairs, cookiePair{Name: c.Name, Value: c.Value, Domain: domain, Path: c.Path, Expires: unixOrZero(c.Expires), Secure: c.Secure, HttpOnly: c.HttpOnly})
 }
 return pairs
}

// jarDump snapshots the whole client jar (all hosts), so cookies picked up on
// redirect hops or scoped to other hosts survive the trip back to Python.
func jarDump(client tls_client.HttpClient, current []*http.Cookie, currentHost string) map[string][]cookiePair {
 dump := map[string][]cookiePair{}
 if jar, ok := client.GetCookieJar().(tls_client.CookieJar); ok {
  for host, jarCookies := range jar.GetAllCookies() {
   if pairs := pairsFrom(jarCookies, host); len(pairs) > 0 { dump[host] = pairs }
  }
 }
 if len(current) > 0 && currentHost != "" { dump[currentHost] = pairsFrom(current, currentHost) }
 return dump
}

// ---------------------------------------------------------------------------
// https-proxy patch: upstream connect.go hardcodes proxy-TLS verification
// (no InsecureSkipVerify), so verify=false could never disable certificate
// checks against https:// proxies. We build the client ourselves with a
// dialer that honors InsecureSkipVerify for the proxy leg.
// ---------------------------------------------------------------------------

// patched sessions: keyed like cffi's clients map so lifecycle stays identical
var patchedSessions = struct {
 sync.Mutex
 m map[string]tls_client.HttpClient
}{m: map[string]tls_client.HttpClient{}}

func createPatchedClient(in src.RequestInput) (tls_client.HttpClient, string, bool, *src.TLSClientError) {
 proxyUrl := ""
 if in.ProxyUrl != nil { proxyUrl = *in.ProxyUrl }
 // ja3_string clients keep the upstream path (custom profiles are private to cffi)
 if !strings.HasPrefix(strings.ToLower(proxyUrl), "https://") || in.TLSClientIdentifier == "" {
  return src.CreateClient(in)
 }
 sessionId := ""
 if in.SessionId != nil { sessionId = *in.SessionId }
 if sessionId == "" { sessionId = fmt.Sprintf("%d", time.Now().UnixNano()) }

 patchedSessions.Lock()
 if existing, ok := patchedSessions.m[sessionId]; ok {
  patchedSessions.Unlock()
  if in.ProxyUrl != nil {
   if setter, ok := existing.(interface{ SetFollowRedirect(bool) }); ok { setter.SetFollowRedirect(in.FollowRedirects) }
  }
  return existing, sessionId, true, nil
 }
 patchedSessions.Unlock()

 profile, ok := profiles.MappedTLSClients[in.TLSClientIdentifier]
 if !ok { profile = profiles.DefaultClientProfile }

 timeoutMs := in.TimeoutMilliseconds
 if timeoutMs == 0 && in.TimeoutSeconds != 0 { timeoutMs = in.TimeoutSeconds * 1000 }
 if timeoutMs == 0 { timeoutMs = 30000 }

 // the proxy leg is deliberately never certificate-verified: the operator picks
 // the proxy, and https:// proxies in the wild (IP hosts, self-signed/domain certs
 // without IP SANs) fail strict verification — every practical TLS client defaults
 // to lenient proxy TLS. Target verification is still governed by InsecureSkipVerify.
 dialer, err := newInsecureHttpsConnectDialer(proxyUrl, time.Duration(timeoutMs)*time.Millisecond, true)
 if err != nil { return nil, sessionId, false, src.NewTLSClientError(err) }

 options := []tls_client.HttpClientOption{
  tls_client.WithClientProfile(profile),
  tls_client.WithTimeoutMilliseconds(timeoutMs),
  tls_client.WithProxyDialerFactory(func(_ string, _ time.Duration, _ *net.TCPAddr, _ http.Header, _ tls_client.Logger) (proxy.ContextDialer, error) {
   return dialer, nil
  }),
  tls_client.WithCookieJar(tls_client.NewCookieJar()),
 }
 if in.WithRandomTLSExtensionOrder { options = append(options, tls_client.WithRandomTLSExtensionOrder()) }
 if in.ForceHttp1 { options = append(options, tls_client.WithForceHttp1()) }
 if in.DisableHttp3 { options = append(options, tls_client.WithDisableHttp3()) }
 if in.WithProtocolRacing { options = append(options, tls_client.WithProtocolRacing()) }
 if !in.FollowRedirects { options = append(options, tls_client.WithNotFollowRedirects()) }
 if in.InsecureSkipVerify { options = append(options, tls_client.WithInsecureSkipVerify()) }
 if in.ServerNameOverwrite != nil && *in.ServerNameOverwrite != "" {
  options = append(options, tls_client.WithServerNameOverwrite(*in.ServerNameOverwrite))
 }
 if in.LocalAddress != nil {
  localAddr, resolveErr := net.ResolveTCPAddr("", *in.LocalAddress)
  if resolveErr != nil { return nil, sessionId, false, src.NewTLSClientError(resolveErr) }
  options = append(options, tls_client.WithLocalAddr(*localAddr))
 }
 tlsClient, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
 if err != nil { return nil, sessionId, false, src.NewTLSClientError(err) }

 patchedSessions.Lock()
 patchedSessions.m[sessionId] = tlsClient
 patchedSessions.Unlock()
 return tlsClient, sessionId, true, nil
}

// insecureDialer: TLS+CONNECT dialer for https:// proxies; proxy certificate
// verification follows skipVerify, target TLS stays with the uTLS client.
type insecureDialer struct {
 proxyUrl   *url.URL
 skipVerify bool
 timeout    time.Duration
}

func newInsecureHttpsConnectDialer(proxyUrlStr string, timeout time.Duration, skipVerify bool) (*insecureDialer, error) {
 parsed, err := url.Parse(proxyUrlStr)
 if err != nil { return nil, err }
 if parsed.Host == "" { return nil, fmt.Errorf("invalid proxy url %q", proxyUrlStr) }
 if parsed.Port() == "" { parsed.Host = net.JoinHostPort(parsed.Host, "443") }
 return &insecureDialer{proxyUrl: parsed, skipVerify: skipVerify, timeout: timeout}, nil
}

// tunneledConn serves bytes buffered during the CONNECT handshake first.
type tunneledConn struct {
 net.Conn
 r *bufio.Reader
}

func (t *tunneledConn) Read(p []byte) (int, error) { return t.r.Read(p) }

func (d *insecureDialer) connect(ctx context.Context, address string) (net.Conn, error) {
 rawDialer := &net.Dialer{Timeout: d.timeout}
 rawConn, err := rawDialer.DialContext(ctx, "tcp", d.proxyUrl.Host)
 if err != nil { return nil, err }
 var conn net.Conn = rawConn
 if d.proxyUrl.Scheme == "https" {
  tlsConn := tls.Client(rawConn, &tls.Config{
   NextProtos:         []string{"http/1.1"},
   ServerName:         d.proxyUrl.Hostname(),
   InsecureSkipVerify: d.skipVerify,
  })
  tlsConn.SetDeadline(time.Now().Add(d.timeout))
  if err := tlsConn.HandshakeContext(ctx); err != nil {
   _ = rawConn.Close()
   return nil, err
  }
  tlsConn.SetDeadline(time.Time{})
  conn = tlsConn
 }
 req := &http.Request{Method: "CONNECT", URL: &url.URL{Host: address}, Header: make(http.Header), Host: address}
 if d.proxyUrl.User != nil {
  password, _ := d.proxyUrl.User.Password()
  req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.proxyUrl.User.Username()+":"+password)))
 }
 reader := bufio.NewReader(conn)
 if err := req.Write(conn); err != nil { _ = conn.Close(); return nil, err }
 resp, err := http.ReadResponse(reader, req)
 if err != nil { _ = conn.Close(); return nil, err }
 if resp.StatusCode != http.StatusOK {
  _ = conn.Close()
  return nil, fmt.Errorf("https proxy responded with non 200 code: %s", resp.Status)
 }
 return &tunneledConn{Conn: conn, r: reader}, nil
}

func (d *insecureDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
 return d.connect(ctx, address)
}

func (d *insecureDialer) Dial(network, address string) (net.Conn, error) {
 return d.connect(context.Background(), address)
}

//export yumeclient_call
func yumeclient_call(input *C.char) *C.char {
 var in src.RequestInput
 if err := json.Unmarshal([]byte(C.GoString(input)), &in); err != nil { return C.CString(`{"status":0,"body":"invalid input"}`) }
 client, session, withSession, clientErr := createPatchedClient(in)
 if clientErr != nil {
  b,_:=json.Marshal(map[string]any{"status":0, "body":"client creation failed: "+clientErr.Error()})
  return C.CString(string(b))
 }
 req, clientErr := src.BuildRequest(in)
 if clientErr != nil {
  if withSession { src.RemoveSession(session) }
  b,_:=json.Marshal(map[string]any{"status":0, "body":clientErr.Error()})
  return C.CString(string(b))
 }
 // upstream cffi never applies input.RequestCookies; seed them into the jar so
 // the first call of a session sends the Python-side cookies (and they survive redirects)
 if len(in.RequestCookies) > 0 {
  jarCookies := make([]*http.Cookie, 0, len(in.RequestCookies))
  for _, c := range in.RequestCookies {
   if c.Name == "" { continue }
   jarCookies = append(jarCookies, &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path})
  }
  if len(jarCookies) > 0 && req.URL != nil { client.SetCookies(req.URL, jarCookies) }
 }
 resp, err := wrapClient(client).Do(req)
 if err != nil {
  if withSession { src.RemoveSession(session); removePatchedSession(session) }
  b,_:=json.Marshal(map[string]any{"status":0, "body":err.Error()})
  return C.CString(string(b))
 }
 cookies := client.GetCookies(resp.Request.URL)
 out, clientErr := src.BuildResponse(session, withSession, resp, cookies, in)
 if clientErr != nil {
  if withSession { src.RemoveSession(session); removePatchedSession(session) }
  b,_:=json.Marshal(map[string]any{"status":0, "body":clientErr.Error()})
  return C.CString(string(b))
 }
 raw, err := json.Marshal(out)
 if err != nil { return C.CString(`{"status":0,"body":"response encoding failed"}`) }
 var payload map[string]any
 if json.Unmarshal(raw, &payload) == nil {
  currentHost := ""
  if resp.Request != nil && resp.Request.URL != nil { currentHost = resp.Request.URL.Hostname() }
  payload["jarDump"] = jarDump(client, cookies, currentHost)
  if raw2, err := json.Marshal(payload); err == nil { raw = raw2 }
 }
 return C.CString(string(raw))
}

func removePatchedSession(session string) {
 patchedSessions.Lock()
 if client, ok := patchedSessions.m[session]; ok {
  client.CloseIdleConnections()
  delete(patchedSessions.m, session)
 }
 patchedSessions.Unlock()
}

// schemeGuard isolates plain-http requests from the https transport state.
// Upstream keys its cached transports by host:443 regardless of scheme, so an
// h2/h3 transport cached from an https call gets handed to an http:// request
// for the same host -> "http2: unsupported scheme" / "protocol negotiated".
// http:// always speaks plain HTTP/1.1 on a fresh dedicated transport here,
// with the SAME cookie jar, timeout and redirect policy as the inner client.
type schemeGuard struct {
 inner tls_client.HttpClient
}

func wrapClient(client tls_client.HttpClient) *schemeGuard { return &schemeGuard{inner: client} }

func httpErrUseLast(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (g *schemeGuard) buildPlainHTTPClient() *http.Client {
 inner := g.inner
 client := &http.Client{Timeout: 30 * time.Second, Transport: http.DefaultTransport.(*http.Transport).Clone()}
 if fr, ok := inner.(interface{ GetFollowRedirect() bool }); ok && !fr.GetFollowRedirect() {
  client.CheckRedirect = httpErrUseLast
 }
 client.Jar = inner.GetCookieJar()
 return client
}

func (g *schemeGuard) Do(req *http.Request) (*http.Response, error) {
 if strings.EqualFold(req.URL.Scheme, "http") {
  return g.buildPlainHTTPClient().Do(req)
 }
 return g.inner.Do(req)
}

//export yumeclient_close
func yumeclient_close(session *C.char) {
 removePatchedSession(C.GoString(session))
 src.RemoveSession(C.GoString(session))
}

//export yumeclient_free
func yumeclient_free(p *C.char) { C.free(unsafe.Pointer(p)) }
func main() {}
