package xio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

var errControlOnlyRawConn = errors.New("control-only raw conn")

// fdSyscallStream exposes a raw fd to shutdownWritePolicy via syscall.Conn.
type fdSyscallStream struct {
	relay.Stream
	fd int
}

func (s fdSyscallStream) SyscallConn() (syscall.RawConn, error) {
	return controlFd(s.fd), nil
}

type controlFd int

func (fd controlFd) Control(f func(uintptr)) error {
	f(uintptr(fd))
	return nil
}

func (controlFd) Read(func(uintptr) bool) error  { return errControlOnlyRawConn }
func (controlFd) Write(func(uintptr) bool) error { return errControlOnlyRawConn }

func wrapShutDown(t *testing.T, inner relay.Stream) relay.Stream {
	t.Helper()
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,shut-down")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := wrapShutPolicy(spec, inner)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

type recordingStream struct {
	writes    [][]byte
	shutdowns int
	closes    int
	readFrom  *bytes.Reader
	writeTo   bytes.Buffer
}

func (s *recordingStream) Read(p []byte) (int, error) {
	if s.readFrom == nil {
		return 0, io.EOF
	}
	return s.readFrom.Read(p)
}

func (s *recordingStream) Write(p []byte) (int, error) {
	s.writes = append(s.writes, append([]byte(nil), p...))
	return s.writeTo.Write(p)
}

func (s *recordingStream) Close() error {
	s.closes++
	return nil
}

func (s *recordingStream) ShutdownWrite() error {
	s.shutdowns++
	return nil
}

func wrapSpec(t *testing.T, spec string, inner relay.Stream) relay.Stream {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := SetupStream(s, inner)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func TestShutNoneDoesNotCloseOnShutdownWrite(t *testing.T) {
	inner := &recordingStream{}
	stream := wrapSpec(t, "TCP:127.0.0.1:9,shut-none", inner)
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if inner.shutdowns != 0 {
		t.Fatalf("ShutdownWrite should be a no-op, got %d", inner.shutdowns)
	}
	if inner.closes != 1 {
		t.Fatalf("Close calls=%d want 1", inner.closes)
	}
}

type failWriteStream struct{ recordingStream }

func (s *failWriteStream) Write(p []byte) (int, error) {
	s.writes = append(s.writes, append([]byte(nil), p...))
	return 0, io.ErrClosedPipe
}

func TestShutNullIgnoresWriteError(t *testing.T) {
	inner := &failWriteStream{}
	stream := wrapSpec(t, "TCP:127.0.0.1:9,shut-null", inner)
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatalf("classic shut-null ignores xiowrite error: %v", err)
	}
	if inner.shutdowns != 0 {
		t.Fatalf("shut-null must not also ShutdownWrite: shutdowns=%d", inner.shutdowns)
	}
	if len(inner.writes) != 1 || len(inner.writes[0]) != 0 {
		t.Fatalf("writes=%v want one empty datagram", inner.writes)
	}
}

func TestIsNotSockMatchesNotSocketError(t *testing.T) {
	if !isNotSock(notSocketError()) {
		t.Fatal("notSocketError must satisfy isNotSock")
	}
	if !isNotSock(fmt.Errorf("shut-down: %w", notSocketError())) {
		t.Fatal("wrapped notSocketError must satisfy isNotSock")
	}
}

func TestShutDownOnPipeReportsNotSocket(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	stream := wrapSpec(t, "PIPE,shut-down", FileStream(w))
	err = stream.ShutdownWrite()
	if err == nil || !isNotSock(err) {
		t.Fatalf("err=%v want not-a-socket", err)
	}
	if _, err := w.Write([]byte("still-open")); err != nil {
		t.Fatalf("pipe must stay open after shut-down: %v", err)
	}
}
