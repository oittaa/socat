//go:build linux

package xio_test

import (
	"testing"
)

func TestABSTRACTListenConnectEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	name := "socat-usecase-" + t.Name()
	startForkListenPIPE(t, ctx, g, "ABSTRACT-LISTEN:"+name+",fork")
	cli := openClient(t, ctx, g, "ABSTRACT-CONNECT:"+name)
	echoLive(t, streamOf(t, cli), []byte("abstract-hi"))
}
