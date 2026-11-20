package profiles

import (
	"time"

	quic "github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/http3"
)

// HTTP3Fingerprint is how a client looks over QUIC and HTTP/3: its ClientHello,
// transport parameters and packet layout, the flow control it announces, and its
// control and QPACK streams.
type HTTP3Fingerprint struct {
	QUIC              *quic.Fingerprint
	InitialPacketSize uint16
	// SrcConnIDLen is the length of the client's connection IDs; every connection
	// gets its own UDP socket (0 is only possible that way).
	SrcConnIDLen int

	StreamReceiveWindow     uint64
	ConnectionReceiveWindow uint64
	MaxIncomingStreams      int64
	MaxIncomingUniStreams   int64
	MaxIdleTimeout          time.Duration
	// Datagrams: max_datagram_frame_size is announced; H3Datagram: SETTINGS_H3_DATAGRAM.
	Datagrams  bool
	H3Datagram bool

	// GreaseSetting appends a reserved setting to SETTINGS.
	GreaseSetting bool
	Control       *http3.ClientFingerprint
	QPACK         *http3.QPACKStreams
}

// WithHTTP3Fingerprint returns the profile with an HTTP/3 fingerprint.
func (c ClientProfile) WithHTTP3Fingerprint(fp *HTTP3Fingerprint) ClientProfile {
	c.http3Fingerprint = fp
	return c
}

// GetHTTP3Fingerprint returns the profile's HTTP/3 fingerprint, nil without one.
func (c ClientProfile) GetHTTP3Fingerprint() *HTTP3Fingerprint {
	return c.http3Fingerprint
}
