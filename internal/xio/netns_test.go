package xio

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func TestWithNetNSNoOption(t *testing.T) {
	called := false
	err := WithNetNS(parse.Spec{}, nil, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("fn not called")
	}
}

func TestWithNetNSEmptyValue(t *testing.T) {
	s := parse.Spec{Options: []parse.Option{{Name: "netns", Has: true, Value: ""}}}
	called := false
	if err := WithNetNS(s, nil, func() error { called = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("fn not called")
	}
}

func TestWithNetNSMissingWarns(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	s := parse.Spec{Options: []parse.Option{{Name: "netns", Has: true, Value: "socat-missing-ns"}}}
	err := WithNetNS(s, &Global{Log: log}, func() error {
		t.Fatal("fn must not run when ns is missing")
		return nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if runtime.GOOS == "linux" {
		if !strings.Contains(err.Error(), "open(") || !strings.Contains(err.Error(), "/run/netns/socat-missing-ns") {
			t.Fatalf("error %v", err)
		}
	} else if !strings.Contains(err.Error(), "Linux") {
		t.Fatalf("error %v", err)
	}
	if !strings.Contains(buf.String(), "option \"netns\" is experimental") {
		t.Fatalf("missing experimental warning:\n%s", buf.String())
	}
}

func TestWithNetNSExperimentalNoWarn(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	s := parse.Spec{Options: []parse.Option{{Name: "netns", Has: true, Value: "socat-missing-ns"}}}
	err := WithNetNS(s, &Global{Log: log, Experimental: true}, func() error {
		t.Fatal("fn must not run when ns is missing")
		return nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(buf.String(), "experimental") {
		t.Fatalf("unexpected warning:\n%s", buf.String())
	}
}

func TestNetNSName(t *testing.T) {
	if _, ok := netnsName(parse.Spec{}); ok {
		t.Fatal("empty spec")
	}
	s := parse.Spec{Options: []parse.Option{{Name: "netns", Has: true, Value: "foo"}}}
	name, ok := netnsName(s)
	if !ok || name != "foo" {
		t.Fatalf("got %q %v", name, ok)
	}
}

func TestFeatureNAMESPACESLinuxOnly(t *testing.T) {
	if runtime.GOOS == "linux" && !FeatureNAMESPACES {
		t.Fatal("WITH_NAMESPACES must be on for Linux")
	}
	if runtime.GOOS != "linux" && FeatureNAMESPACES {
		t.Fatal("WITH_NAMESPACES must be off outside Linux")
	}
}
