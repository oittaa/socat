package proxyopen

import (
	"io"
	"net"
	"sync"
	"time"
)

// reqPipe is the CONNECT request body. Write copies into a bounded buffer
// or, when the buffer is full, rendezvous with Read. A deadline returns only
// this call's copied bytes and drops the rest; nothing stays in flight for a
// later Write to acknowledge.
type reqPipe struct {
	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte
	max     int
	rdl     time.Time
	wdl     time.Time
	rclosed bool
	wclosed bool
	wactive bool
	wsrc    []byte
	wprog   int
}

type reqPipeReader struct{ p *reqPipe }
type reqPipeWriter struct{ p *reqPipe }

func newReqPipe(max int) (*reqPipeReader, *reqPipeWriter) {
	if max < 0 {
		max = 0
	}
	p := &reqPipe{max: max}
	p.cond = sync.NewCond(&p.mu)
	return &reqPipeReader{p}, &reqPipeWriter{p}
}

func (r *reqPipeReader) Read(p []byte) (int, error)  { return r.p.read(p) }
func (r *reqPipeReader) Close() error                { return r.p.closeRead() }
func (w *reqPipeWriter) Write(p []byte) (int, error) { return w.p.write(p) }
func (w *reqPipeWriter) Close() error                { return w.p.closeWrite() }

func (w *reqPipeWriter) SetWriteDeadline(t time.Time) error {
	w.p.mu.Lock()
	w.p.wdl = t
	w.p.cond.Broadcast()
	w.p.mu.Unlock()
	return nil
}

func (p *reqPipe) wait(dl *time.Time) {
	if h := pipeConnWaitHook; h != nil {
		h()
	}
	deadline := *dl
	if err := deadlineErr(deadline); err != nil {
		return
	}
	if deadline.IsZero() {
		p.cond.Wait()
		return
	}
	remain := time.Until(deadline)
	if remain <= 0 {
		return
	}
	timer := time.AfterFunc(remain, func() {
		p.mu.Lock()
		p.cond.Broadcast()
		p.mu.Unlock()
	})
	p.cond.Wait()
	timer.Stop()
}

func (p *reqPipe) writeErr() error {
	if p.wclosed {
		return net.ErrClosed
	}
	if p.rclosed {
		return io.ErrClosedPipe
	}
	return deadlineErr(p.wdl)
}

func (p *reqPipe) write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.wactive {
		if err := p.writeErr(); err != nil {
			return 0, err
		}
		p.wait(&p.wdl)
	}
	p.wactive = true
	defer func() {
		p.wsrc = nil
		p.wactive = false
		p.cond.Broadcast()
	}()
	if err := p.writeErr(); err != nil {
		return 0, err
	}
	if p.max == 0 {
		return p.writeRendezvous(b)
	}
	return p.writeBuffered(b)
}

func (p *reqPipe) writeBuffered(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		if err := p.writeErr(); err != nil {
			return n, err
		}
		space := p.max - len(p.buf)
		if space > 0 {
			take := len(b) - n
			if take > space {
				take = space
			}
			p.buf = append(p.buf, b[n:n+take]...)
			n += take
			p.cond.Broadcast()
			continue
		}
		p.wait(&p.wdl)
	}
	return n, nil
}

func (p *reqPipe) writeRendezvous(b []byte) (int, error) {
	p.wsrc = b
	p.wprog = 0
	for p.wprog < len(b) {
		if err := p.writeErr(); err != nil {
			n := p.wprog
			p.wsrc = nil
			return n, err
		}
		p.cond.Broadcast()
		p.wait(&p.wdl)
	}
	p.wsrc = nil
	return len(b), nil
}

func (p *reqPipe) take(b []byte) int {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		p.cond.Broadcast()
		return n
	}
	if len(p.wsrc) > 0 {
		n := copy(b, p.wsrc)
		p.wsrc = p.wsrc[n:]
		p.wprog += n
		p.cond.Broadcast()
		return n
	}
	return 0
}

func (p *reqPipe) read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if n := p.take(b); n > 0 {
			return n, nil
		}
		if p.wclosed {
			return 0, io.EOF
		}
		if p.rclosed {
			return 0, net.ErrClosed
		}
		if err := deadlineErr(p.rdl); err != nil {
			return 0, err
		}
		p.wait(&p.rdl)
	}
}

func (p *reqPipe) closeWrite() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.wclosed {
		return nil
	}
	p.wclosed = true
	p.wsrc = nil
	p.cond.Broadcast()
	return nil
}

func (p *reqPipe) closeRead() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rclosed {
		return nil
	}
	p.rclosed = true
	p.cond.Broadcast()
	return nil
}
