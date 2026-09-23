package xio_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUDPForkTCPWrapAllowsPeerAfterOneLookup(t *testing.T) {
	allow := serveHostsAllow(t)
	deny := filepath.Join(t.TempDir(), "hosts.deny")
	if err := os.WriteFile(deny, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, g := testCtx(t), testGlobal()
	spec := "UDP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,hosts-allow=" + allow + ",hosts-deny=" + deny
	srv := startForkListenPIPE(t, ctx, g, spec)
	cli := openClient(t, ctx, g, "UDP4:127.0.0.1:"+tcpPort(t, srv)+",bind=127.0.0.1")
	echoLive(t, streamOf(t, cli), []byte("once"))
}
