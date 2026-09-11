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
