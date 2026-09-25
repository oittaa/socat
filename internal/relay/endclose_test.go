package relay

import (
	"io"
	"sync"
	"testing"
	"time"
)

func TestSessionWrapNextSessionClearsLeftoverPoke(t *testing.T) {
	inner := &recordingDeadlineStream{}
	if err := newSessionWrap(inner).Close(); err != nil {
		t.Fatal(err)
	}
	inner.mu.Lock()
	if inner.readDeadline.IsZero() {
		inner.mu.Unlock()
		t.Fatal("Close should poke a read deadline")
	}
	inner.mu.Unlock()

	_ = newSessionWrap(inner)
	inner.mu.Lock()
	gotRead, gotWrite := inner.readDeadline, inner.writeDeadline
	inner.mu.Unlock()
	if !gotRead.IsZero() || !gotWrite.IsZero() {
		t.Fatalf("next wrap left poke deadlines read=%v write=%v", gotRead, gotWrite)
	}
}

// Input that arrives after a session closed belongs to the next session,
// whether or not Close can interrupt the blocked read.
func TestSharedKeepsInputForNextSession(t *testing.T) {
	for name, deadline := range map[string]bool{"deadline": true, "no deadline": false} {
		t.Run(name, func(t *testing.T) {
			started, input := make(chan struct{}, 1), make(chan string, 1)
			read := func(p []byte) (int, error) {
				select {
				case started <- struct{}{}:
				default:
				}
				s, ok := <-input
				if !ok {
					return 0, io.EOF
				}
				return copy(p, s), nil
			}
			var inner Stream = readFuncStream(read)
			if deadline {
				inner = &recordingDeadlineStream{read: read}
			}
			shared := NewShared(inner)
			first := newSessionWrap(shared)
			result := make(chan error, 1)
			go func() { _, err := first.Read(make([]byte, 8)); result <- err }()
			<-started
			_ = first.Close()
			input <- "kept"
			close(input)
			if err := <-result; err != io.EOF {
				t.Fatalf("closed session Read error = %v, want EOF", err)
			}
			buf := make([]byte, 8)
			n, err := newSessionWrap(shared).Read(buf)
			if err != nil || string(buf[:n]) != "kept" {
				t.Fatalf("next session Read = %q, %v; want kept", buf[:n], err)
			}
		})
	}
}

func TestPokeReadDeadlineStopsAtWrappedSession(t *testing.T) {
	inner := &recordingDeadlineStream{}
	s := newCloseSerialStream(newSessionWrap(inner))
	inner.mu.Lock()
	inner.readDeadline = time.Time{}
	inner.mu.Unlock()
	pokeReadDeadline(s)
	inner.mu.Lock()
	got := inner.readDeadline
	inner.mu.Unlock()
	if !got.IsZero() {
		t.Fatalf("pokeReadDeadline wrote through closeSerialStream to the shared endpoint: %v", got)
	}
}

func TestPokeReadDeadlineStillPokesCloseSerialStream(t *testing.T) {
	inner := &recordingDeadlineStream{}
	pokeReadDeadline(newCloseSerialStream(inner))
	inner.mu.Lock()
	got := inner.readDeadline
	inner.mu.Unlock()
	if got.IsZero() {
		t.Fatal("expected poke through closeSerialStream without a session wrap")
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }

type recordingDeadlineStream struct {
	mu            sync.Mutex
	read          func([]byte) (int, error)
	readDeadline  time.Time
	writeDeadline time.Time
}

func (s *recordingDeadlineStream) Read(p []byte) (int, error) {
	if s.read != nil {
		return s.read(p)
	}
	return 0, io.EOF
}

func (*recordingDeadlineStream) Write(p []byte) (int, error) { return len(p), nil }
func (*recordingDeadlineStream) Close() error                { return nil }
func (*recordingDeadlineStream) ShutdownWrite() error        { return nil }

func (s *recordingDeadlineStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	return nil
}

func (s *recordingDeadlineStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline = t
	return nil
}

func (s *recordingDeadlineStream) StreamProps() Props { return Inspect(s) }

// readFuncStream has no deadline or descriptor, so Close cannot interrupt it.
type readFuncStream func([]byte) (int, error)

func (f readFuncStream) Read(p []byte) (int, error) { return f(p) }
func (readFuncStream) Write(p []byte) (int, error)  { return len(p), nil }
func (readFuncStream) Close() error                 { return nil }
func (readFuncStream) ShutdownWrite() error         { return nil }
func (readFuncStream) StreamProps() Props           { return NoProps() }

type oneShotReader struct {
	data []byte
}

func (r *oneShotReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
