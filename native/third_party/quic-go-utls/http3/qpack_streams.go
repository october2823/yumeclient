package http3

import (
	"context"
	"errors"
	"sync"

	"github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/quicvarint"
	"github.com/quic-go/qpack"
)

const (
	settingQPACKMaxTableCapacity = 0x1
	settingQPACKBlockedStreams   = 0x7

	// ErrCodeQPACKEncoderStreamError is QPACK_ENCODER_STREAM_ERROR (RFC 9204).
	ErrCodeQPACKEncoderStreamError ErrCode = 0x201
)

// QPACKStreams describes how a client opens its QPACK encoder and decoder streams.
// The decoder stream exists whenever SETTINGS_QPACK_MAX_TABLE_CAPACITY is sent;
// without a QPACKStreams it is opened when the first instruction is due.
type QPACKStreams struct {
	// Open allocates both streams right after the control stream, before
	// anything is written on them (Chromium allocates control, decoder, encoder).
	Open bool
	// DecoderFirst allocates the decoder stream before the encoder stream.
	DecoderFirst bool
	// Eager writes both stream types at once (Firefox); otherwise a stream's type
	// goes out with its first instruction (Chromium).
	Eager bool
	// ZeroCapacity answers a peer SETTINGS_QPACK_MAX_TABLE_CAPACITY with Set
	// Dynamic Table Capacity 0 on the encoder stream (Chromium).
	ZeroCapacity bool
}

type qpackStreams struct {
	conn  *Conn
	cfg   QPACKStreams
	ready chan struct{} // closed once the streams (if any) are allocated
	once  sync.Once     // closes ready

	mu       sync.Mutex
	encoder  *quic.SendStream
	decoder  *quic.SendStream
	encW     *queuedWriter // writes to encoder (never blocking the caller)
	decW     *queuedWriter // writes to decoder
	encTyped bool
	decTyped bool
	failed   bool
	typed    <-chan struct{} // the second eager stream type was written (yumeclient)
	typedW   *queuedWriter
}

func newQPACKStreams(cfg *QPACKStreams) *qpackStreams {
	q := &qpackStreams{ready: make(chan struct{})}
	if cfg != nil {
		q.cfg = *cfg
	}
	return q
}

// open runs right after the control stream was opened.
// abandon: the control stream could not be opened, nothing will be sent (writers
// waiting for ready return instead of blocking forever).
func (q *qpackStreams) abandon() {
	q.mu.Lock()
	if q.conn == nil {
		q.failed = true
	}
	q.mu.Unlock()
	q.once.Do(func() { close(q.ready) })
}

func (q *qpackStreams) open(conn *Conn) {
	defer q.once.Do(func() { close(q.ready) })
	q.mu.Lock()
	defer q.mu.Unlock()
	q.conn = conn
	if !q.cfg.Open && !q.cfg.Eager {
		return
	}
	var err error
	if q.cfg.DecoderFirst {
		if q.decoder, err = conn.OpenUniStream(); err == nil {
			q.encoder, err = conn.OpenUniStream()
		}
	} else {
		if q.encoder, err = conn.OpenUniStream(); err == nil {
			q.decoder, err = conn.OpenUniStream()
		}
	}
	if err != nil {
		q.failed = true
		return
	}
	if q.cfg.Eager {
		first, second := q.encoder, q.decoder
		firstType, secondType := uint64(streamTypeQPACKEncoderStream), uint64(streamTypeQPACKDecoderStream)
		if q.cfg.DecoderFirst {
			first, second, firstType, secondType = second, first, secondType, firstType
		}
		// two writers: the second type waits for the first, keeping their order
		done, w := q.write(first, quicvarint.Append(nil, firstType))
		w.awaitOrder(conn.Context(), done)
		q.typed, q.typedW = q.write(second, quicvarint.Append(nil, secondType))
		q.encTyped, q.decTyped = true, true
	}
}

// write must be called with q.mu held. The bytes are queued: decoder instructions
// are due while a response is decoded, and a peer withholding stream credit must not
// hold the request (yumeclient).
func (q *qpackStreams) write(str *quic.SendStream, b []byte) (<-chan struct{}, *queuedWriter) {
	w := &q.encW
	if str == q.decoder {
		w = &q.decW
	}
	if *w == nil {
		conn := q.conn
		*w = newQueuedWriter(str, func() {
			go conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeExcessiveLoad), "QPACK stream blocked")
		})
	}
	return (*w).enqueue(b), *w
}

// awaitTypes waits until the stream types of eagerly opened QPACK streams were
// written: neqo sends them before the control stream's SETTINGS.
func (q *qpackStreams) awaitTypes(ctx context.Context) {
	q.mu.Lock()
	done, w := q.typed, q.typedW
	q.mu.Unlock()
	if done != nil {
		w.awaitOrder(ctx, done)
	}
}

// sendDecoder writes decoder instructions (Section Acknowledgment, Insert Count
// Increment, Stream Cancellation).
func (q *qpackStreams) sendDecoder(b []byte) {
	<-q.ready
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failed || q.conn == nil {
		return
	}
	if q.decoder == nil {
		str, err := q.conn.OpenUniStream()
		if err != nil {
			q.failed = true
			return
		}
		q.decoder = str
	}
	if !q.decTyped {
		b = append(quicvarint.Append(nil, streamTypeQPACKDecoderStream), b...)
		q.decTyped = true
	}
	q.write(q.decoder, b)
}

// sendEncoder writes encoder instructions.
func (q *qpackStreams) sendEncoder(b []byte) {
	<-q.ready
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failed || q.conn == nil {
		return
	}
	if q.encoder == nil {
		str, err := q.conn.OpenUniStream()
		if err != nil {
			q.failed = true
			return
		}
		q.encoder = str
	}
	if !q.encTyped {
		b = append(quicvarint.Append(nil, streamTypeQPACKEncoderStream), b...)
		q.encTyped = true
	}
	q.write(q.encoder, b)
}

// onSettings reacts to the peer's SETTINGS.
func (q *qpackStreams) onSettings(s *Settings) {
	if s == nil || !q.cfg.ZeroCapacity {
		return
	}
	if _, ok := s.Other[settingQPACKMaxTableCapacity]; ok {
		q.sendEncoder([]byte{0x20}) // Set Dynamic Table Capacity 0: the encoder never uses the table
	}
}

// readEncoderStream feeds the peer's encoder stream to the decoder.
func (c *Conn) readEncoderStream(str *quic.ReceiveStream) {
	err := c.decoder.ReadEncoderStream(str)
	var ee *qpack.EncoderStreamError
	switch {
	case errors.As(err, &ee):
		c.CloseWithError(quic.ApplicationErrorCode(ErrCodeQPACKEncoderStreamError), ee.Error())
	case err != nil:
		// closed, reset or cut off: a critical stream (RFC 9204 4.2); a no-op when
		// the connection is already gone
		c.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "QPACK encoder stream closed")
	}
}
