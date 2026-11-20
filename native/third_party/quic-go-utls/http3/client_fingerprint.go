package http3

import (
	"context"
	"crypto/rand"
	"math/big"
	mrand "math/rand/v2"

	"github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/quicvarint"
)

// ClientFingerprint makes a client's HTTP/3 control stream look like a particular
// browser's. With it, the legacy PriorityParam / SendGreaseFrames behaviour is off.
type ClientFingerprint struct {
	// GreaseFrame sends a reserved frame type right after SETTINGS, with a random
	// payload of up to GreaseFrameMaxLen bytes.
	GreaseFrame       bool
	GreaseFrameMaxLen int
	// PriorityUpdates sends a PRIORITY_UPDATE frame for every request stream, with
	// the request's priority header value, or DefaultPriority without one (Chrome).
	PriorityUpdates bool
	DefaultPriority string
	// PriorityHeader adds "priority: DefaultPriority" to requests without one.
	PriorityHeader bool
}

const framePriorityUpdate = 0xf0700

func appendFingerprintGreaseFrame(b []byte, maxLen int) []byte {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	b = quicvarint.Append(b, 0x1f*n.Uint64()+0x21)
	l := 0
	if maxLen > 0 {
		l = mrand.IntN(maxLen + 1)
	}
	payload := make([]byte, l)
	rand.Read(payload)
	b = quicvarint.Append(b, uint64(l))
	return append(b, payload...)
}

// sendPriorityUpdate writes a PRIORITY_UPDATE for a request stream on the control
// stream (RFC 9218, 7.1).
// The frame is queued (yumeclient): a peer withholding the control stream's credit
// held every request here, past its timeout.
func (c *ClientConn) sendPriorityUpdate(ctx context.Context, id quic.StreamID, value string) {
	<-c.controlReady // already closed: roundTrip waits for it with fingerprints
	c.controlMu.Lock()
	if c.controlStr == nil {
		c.controlMu.Unlock()
		return
	}
	if c.controlW == nil {
		conn := c.conn
		c.controlW = newQueuedWriter(c.controlStr, func() {
			go conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeExcessiveLoad), "control stream blocked")
		})
	}
	w := c.controlW
	c.controlMu.Unlock()
	payload := quicvarint.Append(nil, uint64(id))
	payload = append(payload, value...)
	b := quicvarint.Append(nil, framePriorityUpdate)
	b = quicvarint.Append(b, uint64(len(payload)))
	b = append(b, payload...)
	// the PRIORITY_UPDATE goes out before the request's HEADERS, as Chromium sends it
	w.awaitOrder(ctx, w.enqueue(b))
}
