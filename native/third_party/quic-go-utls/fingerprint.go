package quic

import (
	crand "crypto/rand"
	"time"

	tls "github.com/bogdanfinn/utls"

	"github.com/bogdanfinn/quic-go-utls/internal/protocol"
	"github.com/bogdanfinn/quic-go-utls/internal/wire"
)

// Fingerprint makes a client's handshake look like a particular QUIC client on
// the wire: its ClientHello, transport parameters, connection ID length, first
// packet number and the layout of its first Initial packets.
type Fingerprint struct {
	// ClientHello returns a fresh uTLS spec of the ClientHello for every connection.
	// Its quic_transport_parameters extension (57) carries the TransportParameters.
	ClientHello func() (*tls.ClientHelloSpec, error)
	// TransportParameters are the client's transport parameters in wire order. The
	// values that drive behaviour (flow control windows, stream limits, idle
	// timeout, datagram support) must agree with the Config.
	TransportParameters []TransportParameter
	// ShuffleTransportParameters sends them in a random order on every connection.
	ShuffleTransportParameters bool
	// DestConnIDLen is the length of the Initial Destination Connection ID
	// (0: random between 8 and 20 bytes).
	DestConnIDLen int
	// FirstPacketNumber is the packet number of the first Initial packet; -1 picks
	// it at random like neqo (Firefox).
	FirstPacketNumber int64
	// PadWithZeros pads datagrams carrying Initial packets with zero bytes after
	// the packets instead of PADDING frames (neqo).
	PadWithZeros bool
	// Chaos is how the first flight of Initial packets is laid out.
	Chaos ChaosMode
}

// A TransportParameter is one transport parameter of a Fingerprint.
type TransportParameter = wire.FingerprintParameter

// Transport parameter value kinds.
const (
	TransportParameterVarint             = wire.FingerprintVarint
	TransportParameterBytes              = wire.FingerprintBytes
	TransportParameterSourceConnectionID = wire.FingerprintSourceConnectionID
	TransportParameterGrease             = wire.FingerprintGrease
	TransportParameterVersionInformation = wire.FingerprintVersionInformation
)

// ChaosMode selects how the ClientHello is spread over the first Initial packets
// (Chromium's "chaos protection").
type ChaosMode uint8

const (
	// ChaosOff sends the ClientHello in order (quic-go's own SNI split aside).
	ChaosOff ChaosMode = iota
	// ChaosSinglePacket splits the ClientHello into CRYPTO frames in random order,
	// mixed with PING and PADDING frames, when it fits one packet; a larger one is
	// sent in order (Chromium before M124).
	ChaosSinglePacket
	// ChaosLastPacket fills the first packets in order and scrambles the last one
	// (Chromium M124 to M131).
	ChaosLastPacket
	// ChaosMultiPacket spreads the ClientHello evenly over the packets — the
	// first one gets its beginning and its end — and scrambles every packet
	// (Chromium M133 on).
	ChaosMultiPacket
	// ChaosSNISlice cuts the ClientHello at the middle of the SNI and sends the
	// second part first, filling the packets evenly (neqo's SNI slicing, Firefox
	// 146 on). No PING or PADDING frames.
	ChaosSNISlice
)

// firstPacketNumber picks the first Initial packet number.
func (fp *Fingerprint) firstPacketNumber() protocol.PacketNumber {
	if fp.FirstPacketNumber >= 0 {
		return protocol.PacketNumber(fp.FirstPacketNumber)
	}
	// neqo: mostly below 32, but up to 1024 one time in eight, never 0
	var r [2]byte
	_, _ = crand.Read(r[:])
	high := int(r[1]) - 224
	if high < 0 {
		high = 0
	}
	return protocol.PacketNumber(int(r[0]&0x1f) + high<<5 + 1)
}

// applyFingerprintParameters makes the parameters this endpoint enforces agree
// with the ones a fingerprint announces.
func applyFingerprintParameters(p *wire.TransportParameters, fp *Fingerprint) {
	if len(fp.TransportParameters) == 0 {
		return
	}
	// what is not announced takes the RFC 9000 default
	p.MaxUDPPayloadSize = protocol.MaxReceivePacketSize
	p.ActiveConnectionIDLimit = protocol.DefaultActiveConnectionIDLimit
	p.MaxAckDelay = protocol.DefaultMaxAckDelay
	p.MaxDatagramFrameSize = protocol.InvalidByteCount
	for _, tp := range fp.TransportParameters {
		if tp.Kind != TransportParameterVarint {
			continue
		}
		switch tp.ID {
		case 0x03: // max_udp_payload_size
			p.MaxUDPPayloadSize = protocol.ByteCount(min(tp.Value, protocol.MaxReceivePacketSize))
		case 0x0b: // max_ack_delay
			p.MaxAckDelay = time.Duration(tp.Value) * time.Millisecond
		case 0x0e: // active_connection_id_limit
			p.ActiveConnectionIDLimit = tp.Value
		case 0x20: // max_datagram_frame_size
			p.MaxDatagramFrameSize = protocol.ByteCount(tp.Value)
		}
	}
}
