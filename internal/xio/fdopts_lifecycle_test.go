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
	tests := []struct {
		spec parse.Spec
		name string
		skip bool
	}{
		{spec: parse.Spec{Type: "OPEN"}, name: "perm", skip: true},
		{spec: parse.Spec{Type: "CREATE"}, name: "perm", skip: true},
		{spec: parse.Spec{Type: "CREATE"}, name: "user", skip: false},
		{spec: parse.Spec{Type: "PIPE", Params: []string{"/tmp/p"}}, name: "user", skip: true},
		{spec: parse.Spec{Type: "PIPE"}, name: "perm", skip: false},
		{spec: parse.Spec{Type: "ECHO"}, name: "group", skip: false},
		{spec: parse.Spec{Type: "PTY"}, name: "perm", skip: true},
		{spec: mustSpec(t, "EXEC:true,pty"), name: "user", skip: true},
		{spec: mustSpec(t, "EXEC:true,ptmx"), name: "user", skip: true},
		{spec: mustSpec(t, "EXEC:true,openpty"), name: "user", skip: true},
		{spec: parse.Spec{Type: "EXEC"}, name: "user", skip: false},
		{spec: parse.Spec{Type: "POSIXMQ-RECV"}, name: "perm", skip: true},
		{spec: parse.Spec{Type: "POSIXMQ-RECV"}, name: "user", skip: false},
		{spec: parse.Spec{Type: "UNIX-LISTEN", Params: []string{"/tmp/x.sock"}}, name: "perm", skip: true},
		{spec: parse.Spec{Type: "UNIX-LISTEN", Params: []string{"@abs"}}, name: "perm", skip: true},
		{spec: parse.Spec{Type: "ABSTRACT-LISTEN", Params: []string{"foo"}}, name: "user", skip: true},
		{spec: parse.Spec{Type: "ABSTRACT-CONNECT", Params: []string{"foo"}}, name: "user", skip: false},
		{spec: parse.Spec{Type: "UDP-RECV"}, name: "perm", skip: false},
	}
	for _, tc := range tests {
		if got := skipDescriptorOwnerOption(tc.spec, tc.name); got != tc.skip {
			t.Errorf("skipDescriptorOwnerOption(%q params=%v, %q)=%v want %v", tc.spec.Type, tc.spec.Params, tc.name, got, tc.skip)
		}
	}
}

func TestHasFDLifecycleOptionsCloexec(t *testing.T) {
	for _, raw := range []string{"FD:3,cloexec", "FD:3,cloexec=0", "TCP:localhost:1,cloexec=1", "OPEN:file,cloexec"} {
		if !hasFDLifecycleOptions(mustSpec(t, raw)) {
			t.Errorf("%s: cloexec must trigger ApplyFDOptions", raw)
		}
	}
}

func TestWrapHidesDescriptorUsesExactAddressFamilies(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{raw: "UDP-RECV:1", want: true},
		{raw: "UNIX-RECV:/tmp/x", want: true},
		{raw: "IP-RECV:1", want: true},
		{raw: "QUIC:localhost:1", want: true},
		{raw: "SOCKET-RECV:2:2:0:x00", want: false},
		{raw: "SOCKET-DATAGRAM:2:2:0:x00", want: false},
		{raw: "PROXY:p:h:1,http-version=2", want: false},
		{raw: "PROXY:p:h:1,http-version=3", want: false},
	}
	for _, tc := range tests {
		spec := mustSpec(t, tc.raw)
		if got := wrapHidesDescriptor(spec); got != tc.want {
			t.Errorf("wrapHidesDescriptor(%q)=%v want %v", tc.raw, got, tc.want)
		}
	}
}

func TestRequiredLifecycleOptionValueRejectsMissingValue(t *testing.T) {
	for _, raw := range []string{"FD:3,user", "FD:3,group", "FD:3,owner", "FD:3,gid"} {
		spec := mustSpec(t, raw)
		if _, err := requiredLifecycleOptionValue(spec.Options[0]); err == nil {
			t.Errorf("%s: missing value accepted", raw)
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
