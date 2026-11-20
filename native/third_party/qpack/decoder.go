package qpack

import (
	"context"
	"fmt"
	"io"
	"sync"

	"golang.org/x/net/http2/hpack"
)

// An invalidIndexError is returned when decoding encounters an invalid index
// (e.g., an index that is out of bounds for the static table).
type invalidIndexError int

func (e invalidIndexError) Error() string {
	return fmt.Sprintf("invalid indexed representation index %d", int(e))
}

// A Decoder decodes QPACK header blocks.
// A Decoder can be reused to decode multiple header blocks on different streams
// on the same connection (e.g., headers then trailers). The zero Decoder (and
// NewDecoder) only knows the static table; NewDynamicDecoder also accepts
// references to the dynamic table.
type Decoder struct {
	mu          sync.Mutex
	maxCapacity uint64 // SETTINGS_QPACK_MAX_TABLE_CAPACITY sent to the peer
	maxBlocked  uint64 // SETTINGS_QPACK_BLOCKED_STREAMS sent to the peer
	capacity    uint64
	size        uint64
	entries     []HeaderField // entries[i] has the absolute index dropped+i
	dropped     uint64
	inserted    uint64
	known       uint64 // Known Received Count, as told to the encoder
	blocked     uint64
	changed     chan struct{} // closed on every insertion and on failure
	failed      error
	send        func([]byte)
	cancelled   map[int64]struct{} // streams already cancelled (one instruction each)
}

// DecodeFunc is a function that decodes the next header field from a header block.
// It should be called repeatedly until it returns io.EOF.
// It returns io.EOF when all header fields have been decoded.
// Any error other than io.EOF indicates a decoding error.
type DecodeFunc func() (HeaderField, error)

// NewDecoder returns a new Decoder.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode returns a function that decodes header fields from the given header block.
// It does not copy the slice; the caller must ensure it remains valid during decoding.
// The block is not acknowledged on the decoder stream: use DecodeStream for that.
func (d *Decoder) Decode(p []byte) DecodeFunc {
	return d.DecodeStream(context.Background(), NoStream, p)
}

func (d *Decoder) parseLiteralHeaderFieldWithoutNameReference(buf []byte) (_ HeaderField, rest []byte, _ error) {
	usesHuffmanForName := buf[0]&0x8 > 0
	name, rest, err := d.readString(buf, 3, usesHuffmanForName)
	if err != nil {
		return HeaderField{}, rest, err
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, rest, io.ErrUnexpectedEOF
	}
	usesHuffmanForVal := buf[0]&0x80 > 0
	val, rest, err := d.readString(buf, 7, usesHuffmanForVal)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: val}, rest, nil
}

func (d *Decoder) readString(buf []byte, n uint8, usesHuffman bool) (string, []byte, error) {
	l, buf, err := readVarInt(n, buf)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(buf)) < l {
		return "", nil, io.ErrUnexpectedEOF
	}
	var val string
	if usesHuffman {
		val, err = hpack.HuffmanDecodeToString(buf[:l])
		if err != nil {
			return "", nil, err
		}
	} else {
		val = string(buf[:l])
	}
	buf = buf[l:]
	return val, buf, nil
}

func (d *Decoder) at(i uint64) (hf HeaderField, ok bool) {
	if i >= uint64(len(staticTableEntries)) {
		return
	}
	return staticTableEntries[i], true
}
