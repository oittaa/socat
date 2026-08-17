package fileopen

import (
	"context"
	"os"
	"testing"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func TestPTYLinkCreatesSymlink(t *testing.T) {
	link := t.TempDir() + "/pty-link"
	ch, err := parse.ParseChannel("PTY,echo=0,opost=0,link=" + link)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.OptionValue("link", "") != link {
		t.Fatalf("link option %q", ch.Single.OptionValue("link", ""))
	}
	g := &xio.Global{Log: logx.New()}
	o, err := xio.OpenChannel(context.Background(), ch, xio.ModeRDWR, g)
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	defer func() { _ = o.Close() }()
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("symlink missing: %v", err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("not a symlink")
	}
	target, _ := os.Readlink(link)
	t.Logf("link %s -> %s", link, target)
}
