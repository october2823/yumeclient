package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"github.com/quic-go/qpack"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type sink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *sink) send(b []byte) { s.mu.Lock(); s.buf.Write(b); s.mu.Unlock() }
func (s *sink) take() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := hex.EncodeToString(s.buf.Bytes())
	s.buf.Reset()
	return out
}

func decodeAll(t *testing.T, fn qpack.DecodeFunc) []qpack.HeaderField {
	t.Helper()
	var out []qpack.HeaderField
	for {
		hf, err := fn()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, hf)
	}
}

// RFC 9204, Appendix B.2-B.4.
func TestQPACKRFCExamples(t *testing.T) {
	var out sink
	d := qpack.NewDynamicDecoder(220, 16, out.send)
	pr, pw := io.Pipe()
	defer pw.Close()
	go d.ReadEncoderStream(pr)
	write := func(s string) {
		if _, err := pw.Write(unhex(t, s)); err != nil {
			t.Fatal(err)
		}
	}

	// B.2: the field section arrives before the inserts it needs: it blocks
	type result struct {
		fields []qpack.HeaderField
		err    error
	}
	res := make(chan result, 1)
	go func() {
		fn := d.DecodeStream(context.Background(), 4, unhex(t, "03811011"))
		var fields []qpack.HeaderField
		for {
			hf, err := fn()
			if err == io.EOF {
				res <- result{fields, nil}
				return
			}
			if err != nil {
				res <- result{nil, err}
				return
			}
			fields = append(fields, hf)
		}
	}()
	time.Sleep(20 * time.Millisecond)
	select {
	case <-res:
		t.Fatal("decoding did not block")
	default:
	}
	write("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468")
	r := <-res
	if r.err != nil {
		t.Fatal(r.err)
	}
	want := []qpack.HeaderField{{Name: ":authority", Value: "www.example.com"}, {Name: ":path", Value: "/sample/path"}}
	if len(r.fields) != 2 || r.fields[0] != want[0] || r.fields[1] != want[1] {
		t.Fatalf("got %v", r.fields)
	}
	if got := out.take(); got != "84" {
		t.Fatalf("decoder stream %q, want Section Acknowledgment 84", got)
	}

	// B.3 + B.4: literal-name insert, duplicate, then a section using both
	write("4a637573746f6d2d6b65790c637573746f6d2d76616c756502")
	for d.InsertCount() < 4 {
		time.Sleep(time.Millisecond)
	}
	fields := decodeAll(t, d.DecodeStream(context.Background(), 8, unhex(t, "050080c181")))
	want = []qpack.HeaderField{{Name: ":authority", Value: "www.example.com"}, {Name: ":path", Value: "/"}, {Name: "custom-key", Value: "custom-value"}}
	if len(fields) != 3 || fields[0] != want[0] || fields[1] != want[1] || fields[2] != want[2] {
		t.Fatalf("got %v", fields)
	}
	if got := out.take(); got != "88" {
		t.Fatalf("decoder stream %q, want 88", got)
	}
	d.CancelStream(8)
	if got := out.take(); got != "48" {
		t.Fatalf("stream cancellation %q, want 48", got)
	}

	// B.5: capacity reduction evicts; a reference to an evicted entry fails
	write("810d637573746f6d2d76616c756532")
	for d.InsertCount() < 5 {
		time.Sleep(time.Millisecond)
	}
	fn := d.DecodeStream(context.Background(), 12, unhex(t, "0200"+"80"))
	if _, err := fn(); err == nil {
		// RIC 1 refers to entry 0, evicted by now
		t.Fatal("expected an error for an evicted entry")
	}
}

func TestQPACKStaticDecoderRejectsDynamicReferences(t *testing.T) {
	_, err := qpack.NewDecoder().Decode(unhex(t, "0381"))()
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestQPACKBlockedLimitAndCancel(t *testing.T) {
	d := qpack.NewDynamicDecoder(220, 1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := d.DecodeStream(ctx, 0, unhex(t, "0200"))(); errc <- err }()
	time.Sleep(20 * time.Millisecond)
	// a second blocked stream exceeds SETTINGS_QPACK_BLOCKED_STREAMS = 1
	_, err := d.DecodeStream(context.Background(), 4, unhex(t, "0200"))()
	var de *qpack.DecompressionError
	if !errors.As(err, &de) {
		t.Fatalf("got %v, want a qpack.DecompressionError", err)
	}
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestQPACKEncoderStreamErrors(t *testing.T) {
	for name, data := range map[string]string{
		"capacity above maximum":  "3fe101",                 // 300 > 220
		"entry larger than table": "3f01" + "4161" + "0161", // capacity 32: entry of 34
		"bad relative index":      "3fbd0100",               // duplicate of nothing
		"bad static index":        "3fbd01ff7f0161",         // static index 190
	} {
		d := qpack.NewDynamicDecoder(220, 16, nil)
		err := d.ReadEncoderStream(bytes.NewReader(unhex(t, data)))
		var ee *qpack.EncoderStreamError
		if !errors.As(err, &ee) {
			t.Errorf("%s: got %v, want an qpack.EncoderStreamError", name, err)
		}
	}
}

func TestQPACKEncoderStreamErrorWithFin(t *testing.T) {
	// the malformed instruction and the stream's end arrive in one read (the FIN in
	// the same STREAM frame): still QPACK_ENCODER_STREAM_ERROR
	for name, data := range map[string]string{
		"varint overflow":  "3f" + strings.Repeat("ff", 10) + "01",
		"bad static index": "3fbd01ff7f0161",
	} {
		d := qpack.NewDynamicDecoder(220, 16, nil)
		err := d.ReadEncoderStream(iotest.DataErrReader(bytes.NewReader(unhex(t, data))))
		var ee *qpack.EncoderStreamError
		if !errors.As(err, &ee) {
			t.Errorf("%s: got %v, want an qpack.EncoderStreamError", name, err)
		}
	}
	// a truncated instruction is the stream's end (H3_CLOSED_CRITICAL_STREAM)
	d := qpack.NewDynamicDecoder(220, 16, nil)
	err := d.ReadEncoderStream(iotest.DataErrReader(bytes.NewReader(unhex(t, "3fbd"))))
	var ee *qpack.EncoderStreamError
	if err == nil || errors.As(err, &ee) {
		t.Errorf("truncated: got %v, want the stream's end", err)
	}
}
