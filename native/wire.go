package main

// Wire-accurate fingerprint reporter (0.4.5).
//
// Every TLS connection a session opens goes through captureDialer, which records
// the first TLS record the client writes (the ClientHello, exactly as it left the
// socket — after utls ApplyPreset, GREASE, padding, forceHttp1 ALPN rewrite and
// extension shuffling). Response.fingerprint is computed from those bytes, so it
// matches what tshark/peet.ws see. When no capture exists (HTTP/3-only path or a
// proxy+racing combination where upstream must own the proxy dialer) the reporter
// falls back to the configured spec and says so via "source": "config".

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	tls "github.com/bogdanfinn/utls"
	proxy "golang.org/x/net/proxy"
)

// ---------------------------------------------------------------------------
// capture
// ---------------------------------------------------------------------------

type helloSink struct {
	mu     sync.Mutex
	last   []byte            // full TLS record (5-byte header + handshake)
	byAddr map[string][]byte // dial target host:port -> its latest ClientHello
	count  int
}

func (s *helloSink) store(addr string, b []byte) {
	cp := append([]byte(nil), b...)
	s.mu.Lock()
	s.last = cp
	if s.byAddr == nil {
		s.byAddr = map[string][]byte{}
	}
	if len(s.byAddr) > 256 { // bound memory on very long multi-host sessions
		s.byAddr = map[string][]byte{}
	}
	s.byAddr[addr] = cp
	s.count++
	s.mu.Unlock()
}

// get returns the hello sent to addr (the response's host:port) when known,
// otherwise the session's latest one.
func (s *helloSink) get(addr string) ([]byte, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.byAddr[addr]; ok {
		return b, s.count
	}
	return s.last, s.count
}

const maxHelloCapture = 1 << 16

type captureConn struct {
	net.Conn
	sink *helloSink
	addr string
	mu   sync.Mutex
	buf  []byte
	done bool
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.done {
		c.buf = append(c.buf, p...)
		if len(c.buf) >= 5 {
			if c.buf[0] != 22 { // not a handshake record: nothing to fingerprint
				c.done, c.buf = true, nil
			} else {
				need := 5 + (int(c.buf[3])<<8 | int(c.buf[4]))
				if len(c.buf) >= need {
					c.sink.store(c.addr, c.buf[:need])
					c.done, c.buf = true, nil
				} else if len(c.buf) > maxHelloCapture {
					c.done, c.buf = true, nil
				}
			}
		}
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

type captureDialer struct {
	inner proxy.ContextDialer
	sink  *helloSink
}

func (d *captureDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &captureConn{Conn: conn, sink: d.sink, addr: addr}, nil
}

func (d *captureDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// helloSinks: client -> *helloSink, removed together with the patched session
var helloSinks sync.Map

func sinkFor(client tls_client.HttpClient) *helloSink {
	if v, ok := helloSinks.Load(client); ok {
		return v.(*helloSink)
	}
	return nil
}

// transportDialOptions returns the proxy/dial options for a session with the
// ClientHello capture installed. The underlying dialer is the same one the
// session used before 0.4.5:
//   - https:// proxy  -> insecureDialer (TLS to proxy, CONNECT, no proxy-leg verify)
//   - http/socks proxy -> upstream's own dialer, obtained from a probe client
//   - direct           -> net.Dialer with the session timeout/local address
// keepUpstreamProxy=true (HTTP/3 racing or a udp proxy through a plain proxy URL)
// leaves upstream WithProxyUrl in charge, because the h3 transport reads the
// proxy URL from config: hiding it behind a dialer factory would send QUIC direct.
// Those sessions report "source": "config".
func transportDialOptions(proxyUrl string, timeoutMs int, localAddr *net.TCPAddr, keepUpstreamProxy bool, sink *helloSink) ([]tls_client.HttpClientOption, bool, error) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	factory := func(inner proxy.ContextDialer) tls_client.HttpClientOption {
		cd := &captureDialer{inner: inner, sink: sink}
		return tls_client.WithProxyDialerFactory(func(_ string, _ time.Duration, _ *net.TCPAddr, _ http.Header, _ tls_client.Logger) (proxy.ContextDialer, error) {
			return cd, nil
		})
	}
	lower := strings.ToLower(proxyUrl)
	switch {
	case strings.HasPrefix(lower, "https://"):
		dialer, err := newInsecureHttpsConnectDialer(proxyUrl, timeout, true)
		if err != nil {
			return nil, false, err
		}
		return []tls_client.HttpClientOption{factory(dialer)}, true, nil
	case proxyUrl != "" && keepUpstreamProxy:
		return []tls_client.HttpClientOption{tls_client.WithProxyUrl(proxyUrl)}, false, nil
	case proxyUrl != "":
		probeOpts := []tls_client.HttpClientOption{
			tls_client.WithProxyUrl(proxyUrl),
			tls_client.WithTimeoutMilliseconds(timeoutMs),
		}
		if localAddr != nil {
			probeOpts = append(probeOpts, tls_client.WithLocalAddr(*localAddr))
		}
		probe, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), probeOpts...)
		if err != nil {
			return nil, false, err
		}
		inner := probe.GetDialer()
		if inner == nil { // defensive: never fall back to a direct connection
			return []tls_client.HttpClientOption{tls_client.WithProxyUrl(proxyUrl)}, false, nil
		}
		return []tls_client.HttpClientOption{factory(inner)}, true, nil
	default:
		nd := &net.Dialer{Timeout: timeout}
		if localAddr != nil {
			nd.LocalAddr = localAddr
		}
		return []tls_client.HttpClientOption{factory(nd)}, true, nil
	}
}

// ---------------------------------------------------------------------------
// one field set, two sources (wire bytes / configured spec)
// ---------------------------------------------------------------------------

type helloFields struct {
	legacyVersion uint16
	ciphers       []uint16
	exts          []uint16 // wire order, GREASE included
	groups        []uint16
	points        []uint8
	sigAlgs       []uint16
	versions      []uint16
	alpn          []string
	hsLen         int
}

func isGrease(v uint16) bool { return v&0x0F0F == 0x0A0A && v>>8 == v&0xFF }

func u16list(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}

func parseClientHelloRecord(rec []byte) (*helloFields, error) {
	if len(rec) < 9 || rec[0] != 22 || rec[5] != 1 {
		return nil, fmt.Errorf("not a ClientHello record")
	}
	hs := rec[5:]
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	body := hs[4:]
	if len(body) < hsLen {
		return nil, fmt.Errorf("truncated ClientHello")
	}
	body = body[:hsLen]
	f := &helloFields{hsLen: hsLen}
	p := 0
	need := func(n int) bool { return p+n <= len(body) }
	if !need(34) {
		return nil, fmt.Errorf("short hello")
	}
	f.legacyVersion = uint16(body[0])<<8 | uint16(body[1])
	p = 34
	if !need(1) {
		return nil, fmt.Errorf("short sid")
	}
	p += 1 + int(body[p])
	if !need(2) {
		return nil, fmt.Errorf("short ciphers")
	}
	cl := int(body[p])<<8 | int(body[p+1])
	p += 2
	if !need(cl) {
		return nil, fmt.Errorf("short ciphers")
	}
	f.ciphers = u16list(body[p : p+cl])
	p += cl
	if !need(1) {
		return nil, fmt.Errorf("short compression")
	}
	p += 1 + int(body[p])
	if !need(2) {
		return f, nil // no extensions
	}
	el := int(body[p])<<8 | int(body[p+1])
	p += 2
	end := p + el
	if end > len(body) {
		return nil, fmt.Errorf("short extensions")
	}
	for p+4 <= end {
		t := uint16(body[p])<<8 | uint16(body[p+1])
		l := int(body[p+2])<<8 | int(body[p+3])
		p += 4
		if p+l > end {
			return nil, fmt.Errorf("bad extension length")
		}
		d := body[p : p+l]
		p += l
		f.exts = append(f.exts, t)
		switch t {
		case 10:
			if len(d) >= 2 {
				f.groups = u16list(d[2:])
			}
		case 11:
			if len(d) >= 1 {
				f.points = append([]uint8(nil), d[1:]...)
			}
		case 13:
			if len(d) >= 2 {
				f.sigAlgs = u16list(d[2:])
			}
		case 43:
			if len(d) >= 1 { // 1-byte list length
				f.versions = u16list(d[1:])
			}
		case 16:
			if len(d) >= 2 {
				q := 2
				for q < len(d) {
					n := int(d[q])
					q++
					if q+n > len(d) {
						break
					}
					f.alpn = append(f.alpn, string(d[q:q+n]))
					q += n
				}
			}
		}
	}
	return f, nil
}

func fieldsFromSpec(spec *tls.ClientHelloSpec) *helloFields {
	f := &helloFields{legacyVersion: 0x0303, ciphers: append([]uint16(nil), spec.CipherSuites...)}
	for _, e := range spec.Extensions {
		f.exts = append(f.exts, extensionID(e))
		switch x := e.(type) {
		case *tls.SupportedCurvesExtension:
			for _, c := range x.Curves {
				f.groups = append(f.groups, uint16(c))
			}
		case *tls.SupportedPointsExtension:
			f.points = append([]uint8(nil), x.SupportedPoints...)
		case *tls.SignatureAlgorithmsExtension:
			for _, s := range x.SupportedSignatureAlgorithms {
				f.sigAlgs = append(f.sigAlgs, uint16(s))
			}
		case *tls.SupportedVersionsExtension:
			f.versions = append([]uint16(nil), x.Versions...)
		case *tls.ALPNExtension:
			f.alpn = append([]string(nil), x.AlpnProtocols...)
		}
	}
	return f
}

func joinU16Dec(v []uint16) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		if isGrease(x) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(x)))
	}
	return strings.Join(parts, "-")
}

// JA3 (Salesforce, as Wireshark/peet.ws): legacy version, ciphers, extensions
// (wire order), groups, point formats; GREASE removed everywhere.
func (f *helloFields) ja3() string {
	pts := make([]string, 0, len(f.points))
	for _, p := range f.points {
		pts = append(pts, strconv.Itoa(int(p)))
	}
	return strings.Join([]string{
		strconv.Itoa(int(f.legacyVersion)), joinU16Dec(f.ciphers), joinU16Dec(f.exts),
		joinU16Dec(f.groups), strings.Join(pts, "-"),
	}, ",")
}

func ja4AlpnTag(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	v := alpn[0]
	first, last := v[0], v[len(v)-1]
	isAlnum := func(c byte) bool { return c < 0x80 && (c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') }
	if !isAlnum(first) || !isAlnum(last) {
		h := hex.EncodeToString([]byte(v))
		return string(h[0]) + string(h[len(h)-1])
	}
	return string(first) + string(last)
}

func sha12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// JA4 (FoxIO spec, matches Wireshark 4.x tls.handshake.ja4):
// t<ver><d|i><cc><ec><alpn>_<sha256(sorted ciphers)>_<sha256(sorted exts w/o SNI,ALPN "_" sigalgs in order)>
// returns ja4 and ja4_r (the unhashed form)
func (f *helloFields) ja4() (string, string) {
	ciphers := []uint16{}
	for _, c := range f.ciphers {
		if !isGrease(c) {
			ciphers = append(ciphers, c)
		}
	}
	exts := []uint16{}
	sni := "i"
	for _, e := range f.exts {
		if isGrease(e) {
			continue
		}
		exts = append(exts, e)
		if e == 0 {
			sni = "d"
		}
	}
	maxVer := f.legacyVersion
	if len(f.versions) > 0 {
		maxVer = 0
		for _, v := range f.versions {
			if !isGrease(v) && v > maxVer {
				maxVer = v
			}
		}
	}
	ver := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}[maxVer]
	if ver == "" {
		ver = "00"
	}
	cc, ec := len(ciphers), len(exts)
	if cc > 99 {
		cc = 99
	}
	if ec > 99 {
		ec = 99
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, cc, ec, ja4AlpnTag(f.alpn))

	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	cs := make([]string, 0, len(ciphers))
	for _, c := range ciphers {
		cs = append(cs, fmt.Sprintf("%04x", c))
	}
	hashExts := []uint16{}
	for _, e := range exts {
		if e != 0 && e != 16 {
			hashExts = append(hashExts, e)
		}
	}
	sort.Slice(hashExts, func(i, j int) bool { return hashExts[i] < hashExts[j] })
	es := make([]string, 0, len(hashExts))
	for _, e := range hashExts {
		es = append(es, fmt.Sprintf("%04x", e))
	}
	sigs := make([]string, 0, len(f.sigAlgs))
	for _, s := range f.sigAlgs {
		if !isGrease(s) {
			sigs = append(sigs, fmt.Sprintf("%04x", s))
		}
	}
	cStr := strings.Join(cs, ",")
	eStr := strings.Join(es, ",")
	if len(sigs) > 0 {
		eStr += "_" + strings.Join(sigs, ",")
	}
	return a + "_" + sha12(cStr) + "_" + sha12(eStr), a + "_" + cStr + "_" + eStr
}

func (f *helloFields) report() map[string]any {
	ja3 := f.ja3()
	ja4, ja4r := f.ja4()
	out := map[string]any{
		"ja3":          ja3,
		"ja3_hash_md5": fmt.Sprintf("%x", md5.Sum([]byte(ja3))),
		"ja4":          ja4,
		"ja4_r":        ja4r,
	}
	exts := make([]int, 0, len(f.exts))
	for _, e := range f.exts {
		exts = append(exts, int(e))
	}
	out["tls_extensions"] = exts
	return out
}
