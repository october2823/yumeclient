package wire

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"

	"github.com/bogdanfinn/quic-go-utls/quicvarint"
)

// FingerprintParameterKind says how a FingerprintParameter's value is produced.
type FingerprintParameterKind uint8

const (
	// FingerprintVarint is a variable-length integer (Value).
	FingerprintVarint FingerprintParameterKind = iota
	// FingerprintBytes is a fixed value (Bytes, possibly empty).
	FingerprintBytes
	// FingerprintSourceConnectionID is initial_source_connection_id: the connection's
	// own source connection ID.
	FingerprintSourceConnectionID
	// FingerprintGrease is a reserved parameter (ID 31 * N + 27) with Len random bytes
	// (a negative Len: a random length up to -Len).
	FingerprintGrease
	// FingerprintVersionInformation is a version_information value: Bytes holds the
	// versions (4 bytes each); every reserved version (0x?a?a?a?a) in it is replaced
	// by a random one, and with Shuffle the available versions (all but the first,
	// chosen, one) are sent in a random order.
	FingerprintVersionInformation
)

// A FingerprintParameter is one transport parameter of a client fingerprint.
type FingerprintParameter struct {
	ID      uint64
	Kind    FingerprintParameterKind
	Value   uint64
	Bytes   []byte
	Len     int
	Shuffle bool
	// Optional leaves a FingerprintVarint out while its Value is 0.
	Optional bool
}

// MarshalFingerprint marshals the client's transport parameters as listed, in
// order (or in a random order with shuffle). Values that drive this endpoint's
// behaviour (flow control windows, stream limits, idle timeout) are expected to
// match p: the caller configures both from the same fingerprint.
func (p *TransportParameters) MarshalFingerprint(params []FingerprintParameter, shuffle bool) []byte {
	if shuffle {
		params = append([]FingerprintParameter(nil), params...)
		mrand.Shuffle(len(params), func(i, j int) { params[i], params[j] = params[j], params[i] })
	}
	b := make([]byte, 0, 256)
	for _, tp := range params {
		switch tp.Kind {
		case FingerprintVarint:
			if tp.Optional && tp.Value == 0 {
				continue
			}
			b = quicvarint.Append(b, tp.ID)
			b = quicvarint.Append(b, uint64(quicvarint.Len(tp.Value)))
			b = quicvarint.Append(b, tp.Value)
		case FingerprintBytes:
			b = appendRawParam(b, tp.ID, tp.Bytes)
		case FingerprintSourceConnectionID:
			b = appendRawParam(b, tp.ID, p.InitialSourceConnectionID.Bytes())
		case FingerprintGrease:
			n := tp.Len
			if n < 0 {
				n = mrand.IntN(-n + 1)
			}
			data := make([]byte, n)
			rand.Read(data)
			b = appendRawParam(b, 27+31*uint64(mrand.Uint32N(1<<16)), data)
		case FingerprintVersionInformation:
			data := append([]byte(nil), tp.Bytes...)
			for i := 0; i+4 <= len(data); i += 4 {
				if v := binary.BigEndian.Uint32(data[i:]); v&0x0f0f0f0f == 0x0a0a0a0a {
					binary.BigEndian.PutUint32(data[i:], greaseVersion())
				}
			}
			if tp.Shuffle && len(data) > 8 {
				n := len(data)/4 - 1
				mrand.Shuffle(n, func(i, j int) {
					a, c := data[4+4*i:8+4*i], data[4+4*j:8+4*j]
					var tmp [4]byte
					copy(tmp[:], a)
					copy(a, c)
					copy(c, tmp[:])
				})
			}
			b = appendRawParam(b, tp.ID, data)
		}
	}
	return b
}

func appendRawParam(b []byte, id uint64, data []byte) []byte {
	b = quicvarint.Append(b, id)
	b = quicvarint.Append(b, uint64(len(data)))
	return append(b, data...)
}

// greaseVersion returns a reserved version 0x?a?a?a?a (RFC 9000, 15).
func greaseVersion() uint32 {
	return mrand.Uint32()&0xf0f0f0f0 | 0x0a0a0a0a
}
