package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func mustSpec(t *testing.T, raw string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSkipDescriptorOwnerOptsClassicTypes(t *testing.T) {
	skip := []parse.Spec{
		{Type: "OPEN"}, {Type: "FILE"}, {Type: "CREATE"}, {Type: "CREAT"},
		{Type: "GOPEN"}, {Type: "PIPE"}, {Type: "FIFO"}, {Type: "ECHO"}, {Type: "PTY"},
		{Type: "POSIXMQ"}, {Type: "POSIXMQ-SEND"}, {Type: "POSIXMQ-RECV"},
		{Type: "UNIX-LISTEN", Params: []string{"/tmp/x.sock"}},
		{Type: "UNIX-L", Params: []string{"/tmp/x.sock"}},
		{Type: "UNIX-RECV", Params: []string{"/tmp/x.sock"}},
		{Type: "UNIX-RECVFROM", Params: []string{"/tmp/x.sock"}},
	}
	for _, spec := range skip {
		if !skipDescriptorOwnerOpts(spec) {
			t.Errorf("skipDescriptorOwnerOpts(%q params=%v)=false want true", spec.Type, spec.Params)
		}
	}
	apply := []parse.Spec{
		{Type: "FD"}, {Type: "STDIO"}, {Type: "STDIN"}, {Type: "STDOUT"},
		{Type: "TCP"}, {Type: "TCP4"}, {Type: "EXEC"}, {Type: "SYSTEM"},
		{Type: "UNIX"}, {Type: "UNIX-CONNECT", Params: []string{"/tmp/x.sock"}},
		{Type: "UNIX-SENDTO", Params: []string{"/tmp/x.sock"}},
		{Type: "UNIX-LISTEN", Params: []string{"@abs"}},
		{Type: "ABSTRACT-LISTEN", Params: []string{"foo"}},
		{Type: "ABSTRACT-CONNECT", Params: []string{"foo"}},
		{Type: "UDP-RECV"}, {Type: "QUIC-LISTEN"},
	}
	for _, spec := range apply {
		if skipDescriptorOwnerOpts(spec) {
			t.Errorf("skipDescriptorOwnerOpts(%q params=%v)=true want false", spec.Type, spec.Params)
		}
	}
}

func TestParseFtruncateLengthLastWinsAcrossAliases(t *testing.T) {
	tests := []struct {
		raw  string
		want int64
	}{
		{raw: "FD:3,ftruncate32=4", want: 4},
		{raw: "FD:3,ftruncate64=5", want: 5},
		{raw: "FD:3,truncate=6", want: 6},
		{raw: "FD:3,ftruncate=10,ftruncate32=3", want: 3},
		{raw: "FD:3,ftruncate64=3,ftruncate=8", want: 8},
		{raw: "FD:3,ftruncate32=2,ftruncate64=7", want: 7},
	}
	for _, tc := range tests {
		n, present, err := parseFtruncateLength(mustSpec(t, tc.raw))
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if !present || n != tc.want {
			t.Fatalf("%s: n=%d present=%v want %d", tc.raw, n, present, tc.want)
		}
	}
}

func TestLastLifecycleOptionModePermLastWins(t *testing.T) {
	o, ok := lastLifecycleOption(mustSpec(t, "FD:3,perm=0644,mode=0600"), "perm", "mode")
	if !ok || o.Value != "0600" {
		t.Fatalf("perm then mode: %+v ok=%v want 0600", o, ok)
	}
	o, ok = lastLifecycleOption(mustSpec(t, "FD:3,mode=0600,perm=0644"), "perm", "mode")
	if !ok || o.Value != "0644" {
		t.Fatalf("mode then perm: %+v ok=%v want 0644", o, ok)
	}
}

func TestLastLifecycleOptionUserUIDOwnerLastWins(t *testing.T) {
	o, ok := lastLifecycleOption(mustSpec(t, "FD:3,uid=1,owner=2,user=3"), "user", "uid", "owner")
	if !ok || o.Value != "3" {
		t.Fatalf("got %+v ok=%v want user=3", o, ok)
	}
	o, ok = lastLifecycleOption(mustSpec(t, "FD:3,user=3,uid=1"), "user", "uid", "owner")
	if !ok || o.Value != "1" {
		t.Fatalf("got %+v ok=%v want uid=1", o, ok)
	}
}
