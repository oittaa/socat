package parse

import (
	"testing"
)

func TestParseSTDIO(t *testing.T) {
	ch, err := ParseChannel("-")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single == nil || ch.Single.Type != "STDIO" {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseFD(t *testing.T) {
	ch, err := ParseChannel("2")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "FD" || ch.Single.Params[0] != "2" {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseTCP4(t *testing.T) {
	// Classic test TCP4 uses TCP4-LISTEN and TCP4:host:port
	ch, err := ParseChannel("TCP4-LISTEN:8080,reuseaddr,fork")
	if err != nil {
		t.Fatal(err)
	}
	s := ch.Single
	if s.Type != "TCP4-LISTEN" {
		t.Fatalf("type %q", s.Type)
	}
	if len(s.Params) != 1 || s.Params[0] != "8080" {
		t.Fatalf("params %v", s.Params)
	}
	if !s.BoolOption("reuseaddr") || !s.BoolOption("fork") {
		t.Fatalf("options %v", s.Options)
	}
}

func TestParseTCPConnect(t *testing.T) {
	ch, err := ParseChannel("TCP4:127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	s := ch.Single
	if s.Type != "TCP4" || len(s.Params) != 2 {
		t.Fatalf("got %+v", s)
	}
	if s.Params[0] != "127.0.0.1" || s.Params[1] != "8080" {
		t.Fatalf("params %v", s.Params)
	}
}

func TestParseDual(t *testing.T) {
	// Classic DUALSTDIO / stdin!!stdout
	ch, err := ParseChannel("stdin!!stdout")
	if err != nil {
		t.Fatal(err)
	}
	if !ch.IsDual() {
		t.Fatal("expected dual")
	}
	if ch.Dual.Left.Type != "STDIN" || ch.Dual.Right.Type != "STDOUT" {
		t.Fatalf("got left=%+v right=%+v", ch.Dual.Left, ch.Dual.Right)
	}
}

func TestParseDualWithOptions(t *testing.T) {
	ch, err := ParseChannel("TCP4:127.0.0.1:9,connect-timeout=1!!STDOUT")
	if err != nil {
		t.Fatal(err)
	}
	if !ch.IsDual() {
		t.Fatal("expected dual")
	}
	if ch.Dual.Left.Type != "TCP4" {
		t.Fatalf("left type %s", ch.Dual.Left.Type)
	}
	if ch.Dual.Left.OptionValue("connect-timeout", "") != "1" {
		t.Fatalf("options %v", ch.Dual.Left.Options)
	}
}

func TestParseGOPEN(t *testing.T) {
	ch, err := ParseChannel("/tmp/foo")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "GOPEN" || ch.Single.Params[0] != "/tmp/foo" {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseQuotedParam(t *testing.T) {
	ch, err := ParseChannel(`EXEC:"echo hello",pty`)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "EXEC" {
		t.Fatalf("type %s", ch.Single.Type)
	}
	if ch.Single.Params[0] != "echo hello" {
		t.Fatalf("param %q", ch.Single.Params[0])
	}
	if !ch.Single.BoolOption("pty") {
		t.Fatal("missing pty")
	}
}

func TestParseIPv6(t *testing.T) {
	ch, err := ParseChannel("TCP6:[::1]:8080")
	if err != nil {
		t.Fatal(err)
	}
	s := ch.Single
	// [::1] may be one param if we don't split inside brackets
	if s.Type != "TCP6" {
		t.Fatalf("type %s", s.Type)
	}
	if len(s.Params) < 1 {
		t.Fatalf("params %v", s.Params)
	}
	// With bracket protection, host is [::1] and port is 8080
	if len(s.Params) != 2 || s.Params[0] != "[::1]" || s.Params[1] != "8080" {
		t.Fatalf("params %v (want [::1] and 8080)", s.Params)
	}
}

func TestParseOptionValue(t *testing.T) {
	ch, err := ParseChannel("TCP-LISTEN:80,bind=127.0.0.1,backlog=10")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.OptionValue("bind", "") != "127.0.0.1" {
		t.Fatal(ch.Single.Options)
	}
	if ch.Single.OptionValue("backlog", "") != "10" {
		t.Fatal(ch.Single.Options)
	}
}

func TestParsePIPE(t *testing.T) {
	ch, err := ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "PIPE" || len(ch.Single.Params) != 0 {
		t.Fatalf("got %+v", ch.Single)
	}
}

func TestParseUNIX(t *testing.T) {
	ch, err := ParseChannel("UNIX-LISTEN:/tmp/sock,unlink-early,mode=777")
	if err != nil {
		t.Fatal(err)
	}
	s := ch.Single
	if s.Type != "UNIX-LISTEN" || s.Params[0] != "/tmp/sock" {
		t.Fatalf("got %+v", s)
	}
	if !s.BoolOption("unlink-early") {
		t.Fatal("unlink-early")
	}
	if s.OptionValue("mode", "") != "777" {
		t.Fatal(s.Options)
	}
}

func TestBangInsideQuotesNotDual(t *testing.T) {
	// !! inside quotes should not split dual
	ch, err := ParseChannel(`EXEC:"echo a!!b"`)
	if err != nil {
		t.Fatal(err)
	}
	if ch.IsDual() {
		t.Fatal("should not be dual")
	}
	if ch.Single.Params[0] != "echo a!!b" {
		t.Fatalf("param %q", ch.Single.Params[0])
	}
}
