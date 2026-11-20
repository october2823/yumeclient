package qpack

// Decoder side of the QPACK dynamic table (RFC 9204): the peer's encoder stream
// fills the table, field sections refer to it, and the decoder stream tells the
// encoder what was received (Section Acknowledgment, Insert Count Increment,
// Stream Cancellation).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2/hpack"
)

// entryOverhead is the per-entry size overhead (RFC 9204, Section 3.2.1).
const entryOverhead = 32

// An EncoderStreamError is a malformed or invalid instruction on the peer's encoder
// stream. The connection must be closed with QPACK_ENCODER_STREAM_ERROR.
type EncoderStreamError struct{ msg string }

func (e *EncoderStreamError) Error() string { return "qpack: encoder stream: " + e.msg }

// A DecompressionError is a field section that cannot be decoded. The connection
// must be closed with QPACK_DECOMPRESSION_FAILED.
type DecompressionError struct{ msg string }

func (e *DecompressionError) Error() string { return "qpack: " + e.msg }

func decompressionError(format string, args ...any) error {
	return &DecompressionError{msg: fmt.Sprintf(format, args...)}
}

// NoStream is the stream ID to pass to DecodeStream for a field section that is
// not acknowledged on the decoder stream.
const NoStream int64 = -1

// NewDynamicDecoder returns a Decoder that accepts references to a dynamic table
// of up to maxCapacity bytes (the SETTINGS_QPACK_MAX_TABLE_CAPACITY sent to the
// peer) and up to maxBlocked blocked streams (SETTINGS_QPACK_BLOCKED_STREAMS).
// send writes decoder instructions to the decoder stream; it must not block on
// the decoder.
func NewDynamicDecoder(maxCapacity, maxBlocked uint64, send func([]byte)) *Decoder {
	return &Decoder{
		maxCapacity: maxCapacity,
		maxBlocked:  maxBlocked,
		send:        send,
		changed:     make(chan struct{}),
	}
}

// MaxCapacity is the dynamic table capacity this decoder accepts.
func (d *Decoder) MaxCapacity() uint64 {
	if d == nil {
		return 0
	}
	return d.maxCapacity
}

// InsertCount is the number of entries inserted into the dynamic table so far.
func (d *Decoder) InsertCount() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inserted
}

// Fail makes blocked and later field sections that need the dynamic table fail
// with err, e.g. when the connection closes.
func (d *Decoder) Fail(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failLocked(err)
}

func (d *Decoder) failLocked(err error) {
	if d.failed != nil {
		return
	}
	d.failed = err
	if d.changed != nil {
		close(d.changed)
		d.changed = make(chan struct{})
	}
}

// ReadEncoderStream processes the peer's encoder stream (without the stream type)
// until it fails. The returned error is an *EncoderStreamError for an invalid
// instruction, or the error that ended the stream (io.EOF if it was closed).
func (d *Decoder) ReadEncoderStream(r io.Reader) error {
	rr := &recordingReader{r: r}
	br := bufio.NewReader(rr)
	err := d.readEncoderStream(br)
	var ee *EncoderStreamError
	if err != nil && !errors.As(err, &ee) && err != rr.err &&
		!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		// the stream is fine, the instruction is not (an integer overflow, bad
		// Huffman): QPACK_ENCODER_STREAM_ERROR, not a closed critical stream
		err = &EncoderStreamError{err.Error()}
	}
	d.Fail(err)
	return err
}

// recordingReader remembers the error that ended the underlying stream.
type recordingReader struct {
	r   io.Reader
	err error
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil {
		r.err = err
	}
	return n, err
}

func (d *Decoder) readEncoderStream(br *bufio.Reader) error {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		switch {
		case b&0x80 != 0: // Insert with Name Reference: 1 T index(6), value
			static := b&0x40 != 0
			index, err := readVarIntFrom(br, 6, b)
			if err != nil {
				return err
			}
			value, err := d.readStringFrom(br, 7)
			if err != nil {
				return err
			}
			var name string
			if static {
				if index >= uint64(len(staticTableEntries)) {
					return &EncoderStreamError{fmt.Sprintf("invalid static table index %d", index)}
				}
				name = staticTableEntries[index].Name
			} else {
				hf, err := d.relative(index)
				if err != nil {
					return err
				}
				name = hf.Name
			}
			if err := d.insert(name, value); err != nil {
				return err
			}
		case b&0x40 != 0: // Insert with Literal Name: 01 H length(5) name, value
			name, err := d.readStringWithFirst(br, 5, b)
			if err != nil {
				return err
			}
			value, err := d.readStringFrom(br, 7)
			if err != nil {
				return err
			}
			if err := d.insert(name, value); err != nil {
				return err
			}
		case b&0x20 != 0: // Set Dynamic Table Capacity: 001 capacity(5)
			capacity, err := readVarIntFrom(br, 5, b)
			if err != nil {
				return err
			}
			if err := d.setCapacity(capacity); err != nil {
				return err
			}
		default: // Duplicate: 000 index(5)
			index, err := readVarIntFrom(br, 5, b)
			if err != nil {
				return err
			}
			hf, err := d.relative(index)
			if err != nil {
				return err
			}
			if err := d.insert(hf.Name, hf.Value); err != nil {
				return err
			}
		}
	}
}

// relative returns the entry at an encoder-stream relative index.
func (d *Decoder) relative(index uint64) (HeaderField, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if index >= d.inserted {
		return HeaderField{}, &EncoderStreamError{fmt.Sprintf("invalid relative index %d", index)}
	}
	abs := d.inserted - 1 - index
	if abs < d.dropped {
		return HeaderField{}, &EncoderStreamError{fmt.Sprintf("reference to evicted entry %d", abs)}
	}
	return d.entries[abs-d.dropped], nil
}

func (d *Decoder) setCapacity(capacity uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if capacity > d.maxCapacity {
		return &EncoderStreamError{fmt.Sprintf("capacity %d exceeds the maximum %d", capacity, d.maxCapacity)}
	}
	d.capacity = capacity
	d.evictLocked(0)
	return nil
}

func (d *Decoder) evictLocked(room uint64) {
	for len(d.entries) > 0 && d.size+room > d.capacity {
		e := d.entries[0]
		d.size -= uint64(len(e.Name)+len(e.Value)) + entryOverhead
		d.entries[0] = HeaderField{}
		d.entries = d.entries[1:]
		d.dropped++
	}
	if len(d.entries) == 0 {
		d.entries = nil
	}
}

func (d *Decoder) insert(name, value string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	size := uint64(len(name)+len(value)) + entryOverhead
	if size > d.capacity {
		return &EncoderStreamError{fmt.Sprintf("entry of %d bytes does not fit the table capacity %d", size, d.capacity)}
	}
	d.evictLocked(size)
	d.entries = append(d.entries, HeaderField{Name: name, Value: value})
	d.size += size
	d.inserted++
	close(d.changed)
	d.changed = make(chan struct{})
	return nil
}

// readStringFrom reads a string literal whose first byte carries the Huffman flag
// above an n-bit length prefix.
func (d *Decoder) readStringFrom(br *bufio.Reader, n uint8) (string, error) {
	first, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	return d.readStringWithFirst(br, n, first)
}

func (d *Decoder) readStringWithFirst(br *bufio.Reader, n uint8, first byte) (string, error) {
	huffman := first&(1<<n) != 0
	length, err := readVarIntFrom(br, n, first)
	if err != nil {
		return "", err
	}
	// an entry never exceeds the table capacity: refuse lengths that could not fit
	if length > d.maxCapacity {
		return "", &EncoderStreamError{fmt.Sprintf("string of %d bytes exceeds the table capacity", length)}
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", err
	}
	if huffman {
		s, err := hpack.HuffmanDecodeToString(buf)
		if err != nil {
			return "", &EncoderStreamError{"invalid Huffman encoding"}
		}
		return s, nil
	}
	return string(buf), nil
}

// readVarIntFrom continues an integer with an n-bit prefix whose first byte has
// already been read.
func readVarIntFrom(br io.ByteReader, n uint8, first byte) (uint64, error) {
	mask := uint64(1)<<n - 1
	i := uint64(first) & mask
	if i < mask {
		return i, nil
	}
	var m uint
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		i += uint64(b&0x7f) << m
		if b&0x80 == 0 {
			return i, nil
		}
		m += 7
		if m >= 63 {
			return 0, errVarintOverflow
		}
	}
}

// requiredInsertCount decodes the Encoded Required Insert Count (RFC 9204, 4.5.1.1).
func (d *Decoder) requiredInsertCountLocked(encoded uint64) (uint64, error) {
	if encoded == 0 {
		return 0, nil
	}
	maxEntries := d.maxCapacity / entryOverhead
	if maxEntries == 0 {
		return 0, errors.New("expected Required Insert Count to be zero")
	}
	fullRange := 2 * maxEntries
	if encoded > fullRange {
		return 0, decompressionError("invalid Required Insert Count %d", encoded)
	}
	maxValue := d.inserted + maxEntries
	maxWrapped := maxValue / fullRange * fullRange
	ric := maxWrapped + encoded - 1
	if ric > maxValue {
		if ric <= fullRange {
			return 0, decompressionError("invalid Required Insert Count %d", encoded)
		}
		ric -= fullRange
	}
	if ric == 0 {
		return 0, decompressionError("invalid Required Insert Count %d", encoded)
	}
	return ric, nil
}

// DecodeStream is Decode for a field section on stream streamID that may refer to
// the dynamic table. The first call blocks until the entries the section needs
// arrive on the encoder stream (or ctx ends). After the last field the section is
// acknowledged on the decoder stream unless streamID is NoStream.
func (d *Decoder) DecodeStream(ctx context.Context, streamID int64, p []byte) DecodeFunc {
	var (
		started bool
		done    bool
		ric     uint64
		base    uint64
	)
	return func() (HeaderField, error) {
		if done {
			return HeaderField{}, io.EOF
		}
		if !started {
			var err error
			ric, base, p, err = d.prefix(ctx, p)
			if err != nil {
				return HeaderField{}, err
			}
			started = true
		}
		if len(p) == 0 {
			done = true
			d.completed(streamID, ric)
			return HeaderField{}, io.EOF
		}
		hf, rest, err := d.parseLine(p, ric, base)
		p = rest
		if err != nil {
			return HeaderField{}, err
		}
		return hf, nil
	}
}

func (d *Decoder) prefix(ctx context.Context, p []byte) (ric, base uint64, rest []byte, err error) {
	encoded, p, err := readVarInt(8, p)
	if err != nil {
		return 0, 0, p, err
	}
	if len(p) == 0 {
		return 0, 0, p, io.ErrUnexpectedEOF
	}
	negative := p[0]&0x80 != 0
	delta, p, err := readVarInt(7, p)
	if err != nil {
		return 0, 0, p, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	ric, err = d.requiredInsertCountLocked(encoded)
	if err != nil {
		return 0, 0, p, err
	}
	if negative {
		if delta >= ric {
			return 0, 0, p, decompressionError("invalid Base")
		}
		base = ric - delta - 1
	} else {
		base = ric + delta
	}
	if ric == 0 {
		return 0, base, p, nil
	}
	if ric > d.inserted {
		if d.failed != nil {
			return 0, 0, p, d.failed
		}
		if d.blocked >= d.maxBlocked {
			return 0, 0, p, decompressionError("too many blocked streams")
		}
		d.blocked++
		defer func() { d.blocked-- }()
		for ric > d.inserted {
			if d.failed != nil {
				return 0, 0, p, d.failed
			}
			changed := d.changed
			d.mu.Unlock()
			select {
			case <-changed:
			case <-ctx.Done():
				d.mu.Lock()
				return 0, 0, p, ctx.Err()
			}
			d.mu.Lock()
		}
	}
	return ric, base, p, nil
}

func (d *Decoder) dynamic(abs, ric uint64) (HeaderField, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if abs >= ric {
		return HeaderField{}, decompressionError("reference to entry %d beyond the Required Insert Count %d", abs, ric)
	}
	if abs < d.dropped || abs-d.dropped >= uint64(len(d.entries)) {
		return HeaderField{}, decompressionError("reference to evicted entry %d", abs)
	}
	return d.entries[abs-d.dropped], nil
}

func (d *Decoder) parseLine(p []byte, ric, base uint64) (HeaderField, []byte, error) {
	b := p[0]
	switch {
	case b&0x80 != 0: // Indexed Field Line: 1 T index(6)
		index, rest, err := readVarInt(6, p)
		if err != nil {
			return HeaderField{}, p, err
		}
		if b&0x40 != 0 {
			hf, ok := d.at(index)
			if !ok {
				return HeaderField{}, p, invalidIndexError(index)
			}
			return hf, rest, nil
		}
		if index >= base {
			return HeaderField{}, p, decompressionError("invalid relative index %d", index)
		}
		hf, err := d.dynamic(base-1-index, ric)
		return hf, rest, err
	case b&0xc0 == 0x40: // Literal Field Line with Name Reference: 01 N T index(4)
		index, rest, err := readVarInt(4, p)
		if err != nil {
			return HeaderField{}, p, err
		}
		var hf HeaderField
		if b&0x10 != 0 {
			var ok bool
			if hf, ok = d.at(index); !ok {
				return HeaderField{}, p, invalidIndexError(index)
			}
		} else {
			if index >= base {
				return HeaderField{}, p, decompressionError("invalid relative index %d", index)
			}
			if hf, err = d.dynamic(base-1-index, ric); err != nil {
				return HeaderField{}, p, err
			}
		}
		return d.literalValue(hf.Name, rest)
	case b&0xe0 == 0x20: // Literal Field Line with Literal Name: 001 N H length(3)
		return d.parseLiteralHeaderFieldWithoutNameReference(p)
	case b&0xf0 == 0x10: // Indexed Field Line with Post-Base Index: 0001 index(4)
		index, rest, err := readVarInt(4, p)
		if err != nil {
			return HeaderField{}, p, err
		}
		hf, err := d.dynamic(base+index, ric)
		return hf, rest, err
	default: // Literal Field Line with Post-Base Name Reference: 0000 N index(3)
		index, rest, err := readVarInt(3, p)
		if err != nil {
			return HeaderField{}, p, err
		}
		hf, err := d.dynamic(base+index, ric)
		if err != nil {
			return HeaderField{}, p, err
		}
		return d.literalValue(hf.Name, rest)
	}
}

func (d *Decoder) literalValue(name string, p []byte) (HeaderField, []byte, error) {
	if len(p) == 0 {
		return HeaderField{}, p, io.ErrUnexpectedEOF
	}
	value, rest, err := d.readString(p, 7, p[0]&0x80 != 0)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: value}, rest, nil
}

// completed acknowledges a decoded field section like Chromium's QPACK decoder:
// a Section Acknowledgment when it referred to the dynamic table, then an Insert
// Count Increment for entries the encoder does not know were received yet.
func (d *Decoder) completed(streamID int64, ric uint64) {
	if d.maxCapacity == 0 {
		return
	}
	d.mu.Lock()
	var b []byte
	if ric > 0 && streamID >= 0 {
		b = appendInstruction(b, 0x80, 7, uint64(streamID))
		if d.known < ric {
			d.known = ric
		}
	}
	if d.known < d.inserted {
		b = appendInstruction(b, 0x00, 6, d.inserted-d.known)
		d.known = d.inserted
	}
	send := d.send
	d.mu.Unlock()
	if len(b) > 0 && send != nil {
		send(b)
	}
}

// CancelStream tells the encoder that the field sections on streamID will not be
// processed (the stream was reset or abandoned).
// Several paths can abandon one stream (a timeout, the body closed early, refused
// trailers): the instruction goes out once.
func (d *Decoder) CancelStream(streamID int64) {
	if d == nil || d.maxCapacity == 0 || d.send == nil || streamID < 0 {
		return
	}
	d.mu.Lock()
	if _, ok := d.cancelled[streamID]; ok {
		d.mu.Unlock()
		return
	}
	if d.cancelled == nil || len(d.cancelled) >= 1024 {
		d.cancelled = map[int64]struct{}{} // old streams are long gone
	}
	d.cancelled[streamID] = struct{}{}
	d.mu.Unlock()
	d.send(appendInstruction(nil, 0x40, 6, uint64(streamID)))
}

func appendInstruction(b []byte, pattern byte, n uint8, v uint64) []byte {
	start := len(b)
	b = appendVarInt(b, n, v)
	b[start] |= pattern
	return b
}
