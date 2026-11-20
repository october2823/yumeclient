package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/textproto"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/httptrace"

	"github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/http3/qlog"
	"github.com/bogdanfinn/quic-go-utls/quicvarint"

	"github.com/quic-go/qpack"
)

const (
	// MethodGet0RTT allows a GET request to be sent using 0-RTT.
	// Note that 0-RTT doesn't provide replay protection and should only be used for idempotent requests.
	MethodGet0RTT = "GET_0RTT"
	// MethodHead0RTT allows a HEAD request to be sent using 0-RTT.
	// Note that 0-RTT doesn't provide replay protection and should only be used for idempotent requests.
	MethodHead0RTT = "HEAD_0RTT"
)

const (
	defaultUserAgent              = "quic-go HTTP/3"
	defaultMaxResponseHeaderBytes = 10 * 1 << 20 // 10 MB
)

type errConnUnusable struct{ e error }

func (e *errConnUnusable) Unwrap() error { return e.e }
func (e *errConnUnusable) Error() string { return fmt.Sprintf("http3: conn unusable: %s", e.e.Error()) }

const max1xxResponses = 5 // arbitrary bound on number of informational responses

var defaultQuicConfig = &quic.Config{
	MaxIncomingStreams: -1, // don't allow the server to create bidirectional streams
	KeepAlivePeriod:    10 * time.Second,
}

// ClientConn is an HTTP/3 client doing requests to a single remote server.
type ClientConn struct {
	conn *Conn

	// Enable support for HTTP/3 datagrams (RFC 9297).
	// If a QUICConfig is set, datagram support also needs to be enabled on the QUIC layer by setting enableDatagrams.
	enableDatagrams bool

	// Additional HTTP/3 settings.
	// It is invalid to specify any settings defined by RFC 9114 (HTTP/3) and RFC 9297 (HTTP Datagrams).
	additionalSettings map[uint64]uint64

	// Order in which to send additional settings
	additionalSettingsOrder []uint64

	// Pseudo-header order for HTTP/3 requests
	pseudoHeaderOrder []string

	// sendGreaseFrames, if true, sends GREASE frames on the HTTP/3 control stream.
	// Chrome sends GREASE frames to maintain protocol extensibility.
	sendGreaseFrames bool

	// priorityParam specifies the PRIORITY header field value to send with requests.
	// If 0, no PRIORITY header is sent.
	priorityParam uint32

	// maxResponseHeaderBytes specifies a limit on how many response bytes are
	// allowed in the server's response header (always enforced).
	maxResponseHeaderBytes int
	// announcedMaxFieldSection: the SETTINGS_MAX_FIELD_SECTION_SIZE this client
	// sends itself, -1 for none (yumeclient: a fingerprint carries its own in
	// additionalSettings)
	announcedMaxFieldSection int64

	// disableCompression, if true, prevents the Transport from requesting compression with an
	// "Accept-Encoding: gzip" request header when the Request contains no existing Accept-Encoding value.
	// If the Transport requests gzip on its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body.
	// However, if the user explicitly requested gzip it is not automatically uncompressed.
	disableCompression bool

	logger *slog.Logger

	requestWriter *requestWriter
	decoder       *qpack.Decoder
	qpack         *qpackStreams

	fingerprint  *ClientFingerprint
	controlReady chan struct{} // closed once setupConn has opened the control stream
	controlMu    sync.Mutex
	controlStr   *quic.SendStream
	controlW     *queuedWriter // later control stream frames (PRIORITY_UPDATE)
}

var _ http.RoundTripper = &ClientConn{}

func newClientConn(
	conn *quic.Conn,
	enableDatagrams bool,
	additionalSettings map[uint64]uint64,
	additionalSettingsOrder []uint64,
	pseudoHeaderOrder []string,
	sendGreaseFrames bool,
	priorityParam uint32,
	streamHijacker func(FrameType, quic.ConnectionTracingID, *quic.Stream, error) (hijacked bool, err error),
	uniStreamHijacker func(StreamType, quic.ConnectionTracingID, *quic.ReceiveStream, error) (hijacked bool),
	maxResponseHeaderBytes int,
	disableCompression bool,
	logger *slog.Logger,
	qpackStreams *QPACKStreams,
	fingerprint *ClientFingerprint,
) *ClientConn {
	c := &ClientConn{
		enableDatagrams:         enableDatagrams,
		additionalSettings:      additionalSettings,
		additionalSettingsOrder: additionalSettingsOrder,
		pseudoHeaderOrder:       pseudoHeaderOrder,
		sendGreaseFrames:        sendGreaseFrames,
		priorityParam:           priorityParam,
		disableCompression:      disableCompression,
		logger:                  logger,
		fingerprint:             fingerprint,
		controlReady:            make(chan struct{}),
	}
	if fingerprint != nil {
		// the fingerprint replaces the legacy Chrome emulation
		c.priorityParam = 0
		c.sendGreaseFrames = false
	}
	if maxResponseHeaderBytes < 0 {
		// Negative value means don't send SETTINGS_MAX_FIELD_SECTION_SIZE. The limit
		// is still enforced (yumeclient: upstream turned it off, and a server could
		// make the client allocate any size): the value the additional SETTINGS
		// announce, else the default.
		c.announcedMaxFieldSection = -1
		c.maxResponseHeaderBytes = defaultMaxResponseHeaderBytes
		if v := additionalSettings[settingMaxFieldSectionSize]; v > 0 && v < uint64(defaultMaxResponseHeaderBytes) {
			c.maxResponseHeaderBytes = int(v)
		}
	} else if maxResponseHeaderBytes == 0 {
		// Zero means use default
		c.maxResponseHeaderBytes = defaultMaxResponseHeaderBytes
		c.announcedMaxFieldSection = int64(c.maxResponseHeaderBytes)
	} else {
		c.maxResponseHeaderBytes = maxResponseHeaderBytes
		c.announcedMaxFieldSection = int64(c.maxResponseHeaderBytes)
	}
	c.decoder = qpack.NewDecoder()
	// The dynamic table the SETTINGS allow the server to use must actually work:
	// a static-only decoder fails every field section that refers to it.
	if capacity := additionalSettings[settingQPACKMaxTableCapacity]; capacity > 0 {
		c.qpack = newQPACKStreams(qpackStreams)
		c.decoder = qpack.NewDynamicDecoder(capacity, additionalSettings[settingQPACKBlockedStreams], c.qpack.sendDecoder)
	}
	c.requestWriter = newRequestWriterWithPseudoHeaderOrder(c.pseudoHeaderOrder, c.priorityParam)
	if fingerprint != nil && fingerprint.PriorityHeader {
		c.requestWriter.priorityValue = fingerprint.DefaultPriority
	}
	c.conn = newConnection(
		conn.Context(),
		conn,
		c.enableDatagrams,
		false, // client
		c.logger,
		0,
	)
	c.conn.decoder = c.decoder
	if c.qpack != nil {
		go func() {
			select {
			case <-c.conn.ReceivedSettings():
				c.qpack.onSettings(c.conn.Settings())
			case <-conn.Context().Done():
			}
		}()
		go func() {
			<-conn.Context().Done()
			c.decoder.Fail(errors.New("http3: connection closed"))
		}()
	}
	// send the SETTINGs frame, using 0-RTT data, if possible
	go func() {
		if err := c.setupConn(); err != nil {
			if c.logger != nil {
				c.logger.Debug("Setting up connection failed", "error", err)
			}
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeInternalError), "")
		}
	}()
	if streamHijacker != nil {
		go c.handleBidirectionalStreams(streamHijacker)
	}
	go c.conn.handleUnidirectionalStreams(uniStreamHijacker)
	return c
}

// OpenRequestStream opens a new request stream on the HTTP/3 connection.
func (c *ClientConn) OpenRequestStream(ctx context.Context) (*RequestStream, error) {
	return c.conn.openRequestStream(ctx, c.requestWriter, nil, c.disableCompression, c.maxResponseHeaderBytes)
}

func (c *ClientConn) setupConn() error {
	defer close(c.controlReady)
	if c.qpack != nil {
		defer c.qpack.abandon() // no-op once open ran
	}
	// open the control stream
	str, err := c.conn.OpenUniStream()
	if err != nil {
		return err
	}
	c.controlMu.Lock()
	defer c.controlMu.Unlock()
	c.controlStr = str
	if c.qpack != nil {
		c.qpack.open(c.conn)
		// eager QPACK stream types go out before the SETTINGS, as neqo sends them
		c.qpack.awaitTypes(c.conn.Context())
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	// send the SETTINGS frame
	b = (&settingsFrame{
		Datagram:            c.enableDatagrams,
		Other:               c.additionalSettings,
		OtherOrder:          c.additionalSettingsOrder,
		MaxFieldSectionSize: c.announcedMaxFieldSection,
	}).Append(b)
	if c.conn.qlogger != nil {
		sf := qlog.SettingsFrame{
			MaxFieldSectionSize: c.announcedMaxFieldSection,
			Other:               maps.Clone(c.additionalSettings),
		}
		if c.enableDatagrams {
			sf.Datagram = pointer(true)
		}
		c.conn.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: str.StreamID(),
			Raw:      qlog.RawInfo{Length: len(b)},
			Frame:    qlog.Frame{Frame: sf},
		})
	}

	// Send PRIORITY_UPDATE frame if priorityParam is set (Chrome behavior)
	// Chrome sends priority information on the control stream
	// Must be sent BEFORE GREASE frames
	if c.priorityParam > 0 {
		if c.logger != nil {
			c.logger.Debug("Sending PRIORITY_UPDATE frame", "priorityParam", c.priorityParam)
		}
		b = appendPriorityUpdateFrame(b, c.priorityParam)
	} else if c.logger != nil {
		c.logger.Debug("NOT sending PRIORITY_UPDATE frame", "priorityParam", c.priorityParam)
	}

	// Send GREASE frames if enabled (Chrome behavior)
	if c.sendGreaseFrames {
		b = appendGreaseFrame(b)
	}
	if c.fingerprint != nil && c.fingerprint.GreaseFrame {
		b = appendFingerprintGreaseFrame(b, c.fingerprint.GreaseFrameMaxLen)
	}

	_, err = str.Write(b)
	return err
}

// appendGreaseFrame appends a GREASE frame to the buffer.
// GREASE frames help maintain protocol extensibility by sending unknown frame types.
// Chrome sends GREASE frames on the control stream after SETTINGS.
func appendGreaseFrame(b []byte) []byte {
	// Generate GREASE frame type: 0x1f * N + 0x21
	// Chrome uses large N values (1-10 billion range)
	greaseFrameType := generateGREASEFrameType()

	// Append frame type
	b = quicvarint.Append(b, greaseFrameType)

	// Append frame length (0 for empty payload, which is common)
	b = quicvarint.Append(b, 0)

	return b
}

// generateGREASEFrameType generates a GREASE frame type.
// GREASE frame types are of the form 0x1f * N + 0x21 where N is a large random number.
func generateGREASEFrameType() uint64 {
	// Chrome uses N in range 1-10 billion
	// This produces frame types like 31000000033, 62000000033, etc.
	n := uint64(1000000000)
	return 0x1f*n + 0x21
}

// appendPriorityUpdateFrame appends a PRIORITY_UPDATE frame to the buffer.
// Chrome sends priority information on the control stream.
// Frame type 0xF0800 (984832) with priority "u=0, i" for request streams.
func appendPriorityUpdateFrame(b []byte, priorityParam uint32) []byte {
	// Frame type: 0xF0800 (984832) for Chrome
	frameType := uint64(priorityParam)

	// Build payload: prioritized_stream_id + priority_field_value
	priorityPayload := make([]byte, 0, 16)

	// Prioritized Element ID: first client-initiated bidirectional stream is always 0
	// (subsequent streams: 4, 8, 12, ...)
	priorityPayload = quicvarint.Append(priorityPayload, 0)

	// Priority Field Value: "u=0, i" as ASCII bytes
	priorityPayload = append(priorityPayload, []byte("u=0, i")...)

	// Append frame type
	b = quicvarint.Append(b, frameType)

	// Append frame length
	b = quicvarint.Append(b, uint64(len(priorityPayload)))

	// Append payload
	b = append(b, priorityPayload...)

	return b
}

func (c *ClientConn) handleBidirectionalStreams(streamHijacker func(FrameType, quic.ConnectionTracingID, *quic.Stream, error) (hijacked bool, err error)) {
	for {
		str, err := c.conn.conn.AcceptStream(context.Background())
		if err != nil {
			if c.logger != nil {
				c.logger.Debug("accepting bidirectional stream failed", "error", err)
			}
			return
		}
		fp := &frameParser{
			r:         str,
			closeConn: c.conn.CloseWithError,
			unknownFrameHandler: func(ft FrameType, e error) (processed bool, err error) {
				id := c.conn.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
				return streamHijacker(ft, id, str, e)
			},
		}
		go func() {
			if _, err := fp.ParseNext(c.conn.qlogger); err == errHijacked {
				return
			}
			if err != nil {
				if c.logger != nil {
					c.logger.Debug("error handling stream", "error", err)
				}
			}
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "received HTTP/3 frame on bidirectional stream")
		}()
	}
}

// RoundTrip executes a request and returns a response
func (c *ClientConn) RoundTrip(req *http.Request) (*http.Response, error) {
	rsp, err := c.roundTrip(req)
	if err != nil && req.Context().Err() != nil {
		// if the context was canceled, return the context cancellation error
		err = req.Context().Err()
	}
	return rsp, err
}

func (c *ClientConn) roundTrip(req *http.Request) (*http.Response, error) {
	// Immediately send out this request, if this is a 0-RTT request.
	switch req.Method {
	case MethodGet0RTT:
		// don't modify the original request
		reqCopy := *req
		req = &reqCopy
		req.Method = http.MethodGet
	case MethodHead0RTT:
		// don't modify the original request
		reqCopy := *req
		req = &reqCopy
		req.Method = http.MethodHead
	default:
		// wait for the handshake to complete
		select {
		case <-c.conn.HandshakeComplete():
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	if c.fingerprint != nil {
		// yumeclient: like a browser, SETTINGS (and the QPACK streams) go out before
		// the first request, not in whatever order the two goroutines get there
		select {
		case <-c.controlReady:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	// It is only possible to send an Extended CONNECT request once the SETTINGS were received.
	// See section 3 of RFC 8441.
	if isExtendedConnectRequest(req) {
		connCtx := c.conn.Context()
		// wait for the server's SETTINGS frame to arrive
		select {
		case <-c.conn.ReceivedSettings():
		case <-connCtx.Done():
			return nil, context.Cause(connCtx)
		}
		if !c.conn.Settings().EnableExtendedConnect {
			return nil, errors.New("http3: server didn't enable Extended CONNECT")
		}
	}

	reqDone := make(chan struct{})
	str, err := c.conn.openRequestStream(
		req.Context(),
		c.requestWriter,
		reqDone,
		c.disableCompression,
		c.maxResponseHeaderBytes,
	)
	if err != nil {
		return nil, &errConnUnusable{e: err}
	}

	// Request Cancellation:
	// This go routine keeps running even after RoundTripOpt() returns.
	// It is shut down when the application is done processing the body.
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-req.Context().Done():
			str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
			str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
			// abandoned before the end: trailers (or the headers) may still refer to
			// the dynamic table (RFC 9204 4.4.2; yumeclient)
			c.decoder.CancelStream(int64(str.StreamID()))
		case <-reqDone:
		}
	}()

	rsp, err := c.doRequest(req, str)
	if err != nil { // if any error occurred
		close(reqDone)
		<-done
		return nil, maybeReplaceError(err)
	}
	return rsp, maybeReplaceError(err)
}

// ReceivedSettings returns a channel that is closed once the server's HTTP/3 settings were received.
// Settings can be obtained from the Settings method after the channel was closed.
func (c *ClientConn) ReceivedSettings() <-chan struct{} {
	return c.conn.ReceivedSettings()
}

// Settings returns the HTTP/3 settings for this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *ClientConn) Settings() *Settings {
	return c.conn.Settings()
}

// CloseWithError closes the connection with the given error code and message.
// It is invalid to call this function after the connection was closed.
func (c *ClientConn) CloseWithError(code ErrCode, msg string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

// Context returns a context that is cancelled when the connection is closed.
func (c *ClientConn) Context() context.Context {
	return c.conn.Context()
}

// cancelingReader reads from the io.Reader.
// It cancels writing on the stream if any error other than io.EOF occurs.
type cancelingReader struct {
	r   io.Reader
	str *RequestStream
}

func (r *cancelingReader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)
	if err != nil && err != io.EOF {
		r.str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
	}
	return n, err
}

func (c *ClientConn) sendRequestBody(str *RequestStream, body io.ReadCloser, contentLength int64) error {
	defer body.Close()
	buf := make([]byte, bodyCopyBufferSize)
	sr := &cancelingReader{str: str, r: body}
	if contentLength == -1 {
		_, err := io.CopyBuffer(str, sr, buf)
		return err
	}

	// make sure we don't send more bytes than the content length
	n, err := io.CopyBuffer(str, io.LimitReader(sr, contentLength), buf)
	if err != nil {
		return err
	}
	var extra int64
	extra, err = io.CopyBuffer(io.Discard, sr, buf)
	n += extra
	if n > contentLength {
		str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
		return fmt.Errorf("http: ContentLength=%d with Body length %d", contentLength, n)
	}
	return err
}

func (c *ClientConn) doRequest(req *http.Request, str *RequestStream) (*http.Response, error) {
	trace := httptrace.ContextClientTrace(req.Context())
	str.ctx = req.Context()
	if fp := c.fingerprint; fp != nil && fp.PriorityUpdates {
		value := req.Header.Get("Priority")
		if value == "" {
			value = fp.DefaultPriority
		}
		c.sendPriorityUpdate(req.Context(), str.StreamID(), value)
	}
	var sendingReqFailed bool
	if err := str.sendRequestHeader(req); err != nil {
		traceWroteRequest(trace, err)
		if c.logger != nil {
			c.logger.Debug("error writing request", "error", err)
		}
		sendingReqFailed = true
	}
	if !sendingReqFailed {
		if req.Body == nil {
			traceWroteRequest(trace, nil)
			str.Close()
		} else {
			// send the request body asynchronously
			go func() {
				contentLength := int64(-1)
				// According to the documentation for http.Request.ContentLength,
				// a value of 0 with a non-nil Body is also treated as unknown content length.
				if req.ContentLength > 0 {
					contentLength = req.ContentLength
				}
				err := c.sendRequestBody(str, req.Body, contentLength)
				traceWroteRequest(trace, err)
				if err != nil {
					if c.logger != nil {
						c.logger.Debug("error writing request", "error", err)
					}
				}
				str.Close()
			}()
		}
	}

	// copy from net/http: support 1xx responses
	var num1xx int // number of informational 1xx headers received
	var res *http.Response
	for {
		var err error
		res, err = str.ReadResponse()
		if err != nil {
			return nil, err
		}
		resCode := res.StatusCode
		is1xx := 100 <= resCode && resCode <= 199
		// treat 101 as a terminal status, see https://github.com/golang/go/issues/26161
		is1xxNonTerminal := is1xx && resCode != http.StatusSwitchingProtocols
		if is1xxNonTerminal {
			num1xx++
			if num1xx > max1xxResponses {
				str.CancelRead(quic.StreamErrorCode(ErrCodeExcessiveLoad))
				str.CancelWrite(quic.StreamErrorCode(ErrCodeExcessiveLoad))
				return nil, errors.New("http3: too many 1xx informational responses")
			}
			traceGot1xxResponse(trace, resCode, textproto.MIMEHeader(res.Header))
			if resCode == http.StatusContinue {
				traceGot100Continue(trace)
			}
			continue
		}
		break
	}
	connState := c.conn.ConnectionState().TLS
	res.TLS = &connState
	res.Request = req
	return res, nil
}

// Conn returns the underlying HTTP/3 connection.
// This method is only useful for advanced use cases, such as when the application needs to
// open streams on the HTTP/3 connection (e.g. WebTransport).
func (c *ClientConn) Conn() *Conn {
	return c.conn
}
