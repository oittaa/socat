package xio_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestOpenSpecSTDOUTWarnsOnReadWrite(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	o, err := xio.OpenSpec(context.Background(), parse.Spec{Type: "STDOUT"}, xio.ModeRDWR, &xio.Global{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if !strings.Contains(buf.String(), "address is opened in read-write mode but only supports write-only") {
		t.Fatalf("log=%q", buf.String())
	}
}

func TestOpenSpecSTDOUTWriteOnlyIsSilent(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	o, err := xio.OpenSpec(context.Background(), parse.Spec{Type: "STDOUT"}, xio.ModeWrite, &xio.Global{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if strings.Contains(buf.String(), "only supports") {
		t.Fatalf("unexpected warning: %q", buf.String())
	}
}

func TestOpenSpecSTDINWarnsOnReadWrite(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	o, err := xio.OpenSpec(context.Background(), parse.Spec{Type: "STDIN"}, xio.ModeRDWR, &xio.Global{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if !strings.Contains(buf.String(), "address is opened in read-write mode but only supports read-only") {
		t.Fatalf("log=%q", buf.String())
	}
}
