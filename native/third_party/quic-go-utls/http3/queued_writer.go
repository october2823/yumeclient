package http3

import (
	"context"
	"sync"
	"time"

	"github.com/bogdanfinn/quic-go-utls"
)

// maxQueuedStreamBytes bounds what waits for a peer's stream credit on one of our
// unidirectional streams; past it the connection is closed.
const maxQueuedStreamBytes = 64 << 10

// queuedWriter writes to one of our unidirectional streams (QPACK encoder and
// decoder, control) from its own goroutine (yumeclient). The writes are due on the
// request path - Section Acknowledgments while a response is decoded, a
// PRIORITY_UPDATE before every request - and a peer that withholds stream credit
// blocked them, and the request with them, past every timeout. The goroutine ends
// when the queue is empty or the stream fails (the connection closing).
type queuedWriter struct {
	str     *quic.SendStream
	onStuck func() // the queue overflowed: the peer stopped reading the stream

	mu      sync.Mutex
	queue   []byte
	waiters []chan struct{} // closed once the queued bytes were written (or failed)
	running bool
	failed  bool
	stalled bool // a write did not go through in orderWait: the peer withholds credit
}

// orderWait bounds how long a request waits for a frame it must follow (its
// PRIORITY_UPDATE): a write normally goes through at once, as the stream buffers it.
const orderWait = 50 * time.Millisecond

// awaitOrder waits until done (a frame queued on w was written) so that what follows
// on another stream goes out after it. A peer withholding the stream's credit holds
// the write: then the wait ends after orderWait (or with ctx) and later frames do not
// wait until a write goes through again - Chromium's HEADERS do not wait for a
// blocked control stream either.
func (w *queuedWriter) awaitOrder(ctx context.Context, done <-chan struct{}) {
	if w == nil {
		return
	}
	w.mu.Lock()
	stalled := w.stalled
	w.mu.Unlock()
	if stalled {
		return
	}
	t := time.NewTimer(orderWait)
	defer t.Stop()
	select {
	case <-done:
	case <-ctx.Done():
	case <-t.C:
		w.mu.Lock()
		w.stalled = true
		w.mu.Unlock()
	}
}

var closedChan = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

func newQueuedWriter(str *quic.SendStream, onStuck func()) *queuedWriter {
	return &queuedWriter{str: str, onStuck: onStuck}
}

// enqueue queues b; the returned channel is closed once b was handed to the stream
// (or the writer failed), so a caller that must keep the order across streams -
// PRIORITY_UPDATE before its request's HEADERS - can wait for it with a deadline.
func (w *queuedWriter) enqueue(b []byte) <-chan struct{} {
	if w == nil || len(b) == 0 {
		return closedChan
	}
	w.mu.Lock()
	if w.failed {
		w.mu.Unlock()
		return closedChan
	}
	if len(w.queue)+len(b) > maxQueuedStreamBytes {
		waiters := w.waiters
		w.failed, w.queue, w.waiters = true, nil, nil
		w.mu.Unlock()
		release(waiters)
		if w.onStuck != nil {
			w.onStuck()
		}
		return closedChan
	}
	done := make(chan struct{})
	w.queue = append(w.queue, b...)
	w.waiters = append(w.waiters, done)
	if !w.running {
		w.running = true
		go w.run()
	}
	w.mu.Unlock()
	return done
}

func release(waiters []chan struct{}) {
	for _, c := range waiters {
		close(c)
	}
}

func (w *queuedWriter) run() {
	for {
		w.mu.Lock()
		b, waiters := w.queue, w.waiters
		w.queue, w.waiters = nil, nil
		if len(b) == 0 || w.failed {
			w.running = false
			w.mu.Unlock()
			release(waiters)
			return
		}
		w.mu.Unlock()
		_, err := w.str.Write(b)
		w.mu.Lock()
		w.stalled = false
		w.mu.Unlock()
		release(waiters)
		if err != nil {
			w.mu.Lock()
			rest := w.waiters
			w.failed, w.queue, w.waiters, w.running = true, nil, nil, false
			w.mu.Unlock()
			release(rest)
			return
		}
	}
}
