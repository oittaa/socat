package xio

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

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
	stream, err := WrapCommon(s, inner)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func TestSelectedShutPolicyOrderAndZero(t *testing.T) {
	tests := []struct {
		spec string
		want shutPolicy
	}{
		{spec: "TCP:127.0.0.1:9", want: shutUnspecified},
		{spec: "TCP:127.0.0.1:9,shut-none", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut-down", want: shutDown},
		{spec: "TCP:127.0.0.1:9,shut-close", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut-null", want: shutNull},
		{spec: "TCP:127.0.0.1:9,shut=none", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut=down", want: shutDown},
		{spec: "TCP:127.0.0.1:9,shut=close", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut=null", want: shutNull},
		{spec: "TCP:127.0.0.1:9,shut-none,shut-close", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut-close,shut-none", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut-null,shut-down", want: shutDown},
		{spec: "TCP:127.0.0.1:9,shut-down,shut-null", want: shutNull},
		{spec: "TCP:127.0.0.1:9,shut=close,shut-none", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut-none,shut=close", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut-none,shut-close=0", want: shutNone},
		{spec: "TCP:127.0.0.1:9,shut-close,shut-none=0", want: shutClose},
		{spec: "TCP:127.0.0.1:9,shut-down=0,shut-null", want: shutNull},
		{spec: "TCP:127.0.0.1:9,shut=0,shut-down", want: shutDown},
		{spec: "TCP:127.0.0.1:9,shut-null,shut=0", want: shutNull},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			s, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			got, err := selectedShutPolicy(s)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("policy=%d want %d", got, tc.want)
			}
		})
	}
}

func TestSelectedShutPolicyInvalidValue(t *testing.T) {
	s, err := parse.ParseSpec("TCP:127.0.0.1:9,shut=foo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectedShutPolicy(s); err == nil {
		t.Fatal("expected error for shut=foo")
	}
	if _, err := WrapCommon(s, &recordingStream{}); err == nil {
		t.Fatal("WrapCommon should reject shut=foo")
	}
}

func TestShutPolicyStreamActions(t *testing.T) {
	tests := []struct {
		spec      string
		shutdowns int
		closes    int
		nilWrite  bool
	}{
		{spec: "TCP:127.0.0.1:9,shut-none", shutdowns: 0, closes: 0},
		{spec: "TCP:127.0.0.1:9,shut-down", shutdowns: 1, closes: 0},
		{spec: "TCP:127.0.0.1:9,shut-close", shutdowns: 0, closes: 1},
		{spec: "TCP:127.0.0.1:9,shut-null", shutdowns: 1, closes: 0, nilWrite: true},
		{spec: "TCP:127.0.0.1:9,shut=none", shutdowns: 0, closes: 0},
		{spec: "TCP:127.0.0.1:9,shut=down", shutdowns: 1, closes: 0},
		{spec: "TCP:127.0.0.1:9,shut=close", shutdowns: 0, closes: 1},
		{spec: "TCP:127.0.0.1:9,shut=null", shutdowns: 1, closes: 0, nilWrite: true},
		{spec: "TCP:127.0.0.1:9,shut-null,shut-close", shutdowns: 0, closes: 1},
		{spec: "TCP:127.0.0.1:9,shut-close,shut-null", shutdowns: 1, closes: 0, nilWrite: true},
		{spec: "TCP:127.0.0.1:9,shut-close,shut-none", shutdowns: 0, closes: 0},
		{spec: "TCP:127.0.0.1:9,shut-none,shut-close=0", shutdowns: 0, closes: 0},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			inner := &recordingStream{}
			stream := wrapSpec(t, tc.spec, inner)
			if err := stream.ShutdownWrite(); err != nil {
				t.Fatal(err)
			}
			if inner.shutdowns != tc.shutdowns || inner.closes != tc.closes {
				t.Fatalf("shutdowns=%d closes=%d want shutdowns=%d closes=%d",
					inner.shutdowns, inner.closes, tc.shutdowns, tc.closes)
			}
			gotNil := false
			for _, w := range inner.writes {
				if len(w) == 0 {
					gotNil = true
				}
			}
			if gotNil != tc.nilWrite {
				t.Fatalf("nil write=%v want %v", gotNil, tc.nilWrite)
			}
		})
	}
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

func TestShutPolicyPreservesDeadlineUnwrap(t *testing.T) {
	for _, opt := range []string{"shut-none", "shut-down", "shut-close", "shut-null", "shut=down"} {
		t.Run(opt, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			spec := parse.Spec{Options: []parse.Option{
				{Name: "rcvtimeo", Value: "0.02", Has: true},
				{Name: "sndtimeo", Value: "0.02", Has: true},
			}}
			parsed, err := parse.ParseSpec("TCP:127.0.0.1:9," + opt)
			if err != nil {
				t.Fatal(err)
			}
			spec.Options = append(spec.Options, parsed.Options...)
			stream, err := WrapCommon(spec, timeoutPipeStream(client))
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			if found, err := relay.SetStreamReadDeadline(stream, deadline); err != nil || !found {
				t.Fatalf("SetStreamReadDeadline found=%v err=%v", found, err)
			}
			if found, err := relay.SetStreamWriteDeadline(stream, deadline); err != nil || !found {
				t.Fatalf("SetStreamWriteDeadline found=%v err=%v", found, err)
			}
		})
	}
}

func TestShutNoneSelectedForExec(t *testing.T) {
	none, err := parse.ParseSpec("EXEC:true,shut-none")
	if err != nil {
		t.Fatal(err)
	}
	if !ShutNoneSelected(none) {
		t.Fatal("shut-none should select EXEC wait-without-kill")
	}
	over, err := parse.ParseSpec("EXEC:true,shut-none,shut-close")
	if err != nil {
		t.Fatal(err)
	}
	if ShutNoneSelected(over) {
		t.Fatal("later shut-close should win over shut-none")
	}
	rev, err := parse.ParseSpec("EXEC:true,shut-close,shut=none")
	if err != nil {
		t.Fatal(err)
	}
	if !ShutNoneSelected(rev) {
		t.Fatal("later shut=none should win")
	}
	off, err := parse.ParseSpec("EXEC:true,shut-none=0")
	if err != nil {
		t.Fatal(err)
	}
	if ShutNoneSelected(off) {
		t.Fatal("shut-none=0 must not select")
	}
}
