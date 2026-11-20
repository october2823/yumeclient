package tls_client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

// yumeclient: HTTP/2 over cleartext TCP with prior knowledge (RFC 9113 section
// 3.3), the way OkHttp's Protocol.H2_PRIOR_KNOWLEDGE and gRPC speak to http://
// servers. The connection preface carries this round tripper's HTTP/2 fingerprint
// (SETTINGS and their order, WINDOW_UPDATE, PRIORITY frames, pseudo-header order,
// HEADERS priority) and goes through its dialer (proxy, local address).

type h2cState struct {
	mu sync.Mutex
	t2 *http2.Transport
}

// H2C returns the session's h2c round tripper (created on first use).
func (rt *roundTripper) H2C() http.RoundTripper {
	rt.h2c.mu.Lock()
	if rt.h2c.t2 == nil {
		rt.h2c.t2 = rt.newH2CTransport()
	}
	t2 := rt.h2c.t2
	rt.h2c.mu.Unlock()
	return &h2cTransport{rt: rt, t2: t2}
}

func (rt *roundTripper) newH2CTransport() *http2.Transport {
	t2 := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return rt.dialH2C(ctx, network, addr)
		},
		DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
			return rt.dialH2C(context.Background(), network, addr)
		},
		ConnectionFlow:  rt.connectionFlow,
		HeaderPriority:  rt.headerPriority,
		IdleConnTimeout: defaultIdleConnectionTimeout,
		InitialStreamID: rt.initialStreamID,
		Priorities:      rt.priorities,
		PushHandler:     &http2.DefaultPushHandler{},
	}
	if rt.transportOptions != nil {
		t2.DisableCompression = rt.transportOptions.DisableCompression
		if rt.transportOptions.IdleConnTimeout != nil {
			t2.IdleConnTimeout = *rt.transportOptions.IdleConnTimeout
		}
	}
	t2.PseudoHeaderOrder = rt.pseudoHeaderOrder
	if t2.PseudoHeaderOrder == nil {
		t2.PseudoHeaderOrder = []string{}
	}
	if rt.settings == nil {
		// same defaults as the TLS transport
		t2.Settings = map[http2.SettingID]uint32{
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingHeaderTableSize:      65536,
		}
		for k := range t2.Settings {
			t2.SettingsOrder = append(t2.SettingsOrder, k)
		}
	} else {
		t2.Settings, t2.SettingsOrder = rt.settings, rt.settingsOrder
	}
	return t2
}

func (rt *roundTripper) dialH2C(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := rt.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &h2cConn{Conn: conn, addr: addr}, nil
}

type h2cTransport struct {
	rt *roundTripper
	t2 *http2.Transport
}

func (t *h2cTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.rt.cachedTransportsLck.Lock()
	closed := t.rt.closed
	t.rt.cachedTransportsLck.Unlock()
	if closed {
		return nil, errClosed
	}
	return t.t2.RoundTrip(req)
}

func (t *h2cTransport) CloseIdleConnections() { t.t2.CloseIdleConnections() }

// closeH2C closes the idle h2c connections (Close / CloseIdleConnections).
func (rt *roundTripper) closeH2C() {
	rt.h2c.mu.Lock()
	t2 := rt.h2c.t2
	rt.h2c.mu.Unlock()
	if t2 != nil {
		t2.CloseIdleConnections()
	}
}

// H2CRefusedError: the server did not answer the h2c connection preface with an
// HTTP/2 SETTINGS frame (it speaks HTTP/1.1 only, or closed the connection).
type H2CRefusedError struct {
	Addr   string
	Detail string
}

func (e *H2CRefusedError) Error() string {
	return fmt.Sprintf("%s does not speak HTTP/2 over cleartext (h2c prior knowledge): %s", e.Addr, e.Detail)
}

// h2cConn checks that the server's first frame is SETTINGS (RFC 9113 3.4).
type h2cConn struct {
	net.Conn
	addr    string
	checked bool
	pending []byte
}

func (c *h2cConn) Read(p []byte) (int, error) {
	if !c.checked {
		c.checked = true
		var head [9]byte
		n, err := io.ReadFull(c.Conn, head[:])
		if err != nil {
			detail := "the server closed the connection"
			if n > 0 {
				detail = fmt.Sprintf("the server answered %q", head[:n])
			} else if !errors.Is(err, io.EOF) {
				return 0, err
			}
			return 0, &H2CRefusedError{Addr: c.addr, Detail: detail}
		}
		if head[3] != 0x4 || head[4]&0x1 != 0 || binary.BigEndian.Uint32(head[5:])&0x7fffffff != 0 {
			return 0, &H2CRefusedError{Addr: c.addr, Detail: fmt.Sprintf("the server answered %q", head[:])}
		}
		c.pending = head[:]
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// DialPlain opens a plain TCP connection through the round tripper's dialer (proxy,
// local address): yumeclient's http:// transport uses it for SOCKS proxies, which
// the plain net/http transport only knows as socks5://.
func (rt *roundTripper) DialPlain(ctx context.Context, network, addr string) (net.Conn, error) {
	return rt.dial(ctx, network, addr)
}
