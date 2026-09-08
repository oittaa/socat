package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

func TestCLILockSamePathAsAddressLockfileFails(t *testing.T) {
	path := testutil.UnixSocketPath(t, "shared.lock")
	unlock, err := acquireLockFiles(context.Background(), &Config{LockFile: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)
	spec := parse.Spec{
		Type:    "ECHO",
		Options: []parse.Option{{Name: "lockfile", Value: path, Has: true}},
	}
	_, err = xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("error=%v want lockfile exists", err)
	}
}
