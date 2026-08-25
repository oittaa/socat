//go:build linux

package xio_test

import (
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func TestABSTRACTListenConnectEcho(t *testing.T) {
	if !xio.FeatureABSTRACT {
		t.Skip("ABSTRACT not enabled")
	}
	ctx, g := testCtx(t), testGlobal()
	name := "socat-usecase-" + t.Name()
	startForkListenPIPE(t, ctx, g, "ABSTRACT-LISTEN:"+name+",fork")
	cli := openClient(t, ctx, g, "ABSTRACT-CONNECT:"+name)
	echoLive(t, streamOf(t, cli), []byte("abstract-hi"))
}
