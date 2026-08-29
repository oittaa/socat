//go:build linux || darwin

package xio

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestControlMessageBytesTruncated(t *testing.T) {
	oob := []byte{0x01, 0x02, 0x03, 0x04}
	if got := ControlMessageBytes(oob, len(oob), unix.MSG_CTRUNC); got != nil {
		t.Fatalf("MSG_CTRUNC returned %v; truncated ancillary must not be parsed", got)
	}
	got := ControlMessageBytes(oob, 2, 0)
	if !bytes.Equal(got, oob[:2]) {
		t.Fatalf("got %v want %v", got, oob[:2])
	}
	if ControlMessageBytes(oob, 0, 0) != nil {
		t.Fatal("oobn=0 must return nil")
	}
}

func TestNeedAncillaryIPv6RecvExtBoolOption(t *testing.T) {
	on, err := parse.ParseSpec("UDP6:[::1]:1,ipv6-recvdstopts")
	if err != nil {
		t.Fatal(err)
	}
	if !NeedAncillary(on) {
		t.Fatal("bare ipv6-recvdstopts must enable ReadMsg")
	}
	alias, err := parse.ParseSpec("UDP6:[::1]:1,recvhopopts=1")
	if err != nil {
		t.Fatal(err)
	}
	if !NeedAncillary(alias) {
		t.Fatal("recvhopopts=1 must enable ReadMsg")
	}
	off, err := parse.ParseSpec("UDP6:[::1]:1,ipv6-recvrthdr=0")
	if err != nil {
		t.Fatal(err)
	}
	if NeedAncillary(off) {
		t.Fatal("ipv6-recvrthdr=0 must not enable ReadMsg")
	}
	lastOff, err := parse.ParseSpec("UDP6:[::1]:1,ipv6-recvdstopts=1,recvdstopts=0")
	if err != nil {
		t.Fatal(err)
	}
	if NeedAncillary(lastOff) {
		t.Fatal("recvdstopts=0 must win and disable ReadMsg")
	}
	lastOn, err := parse.ParseSpec("UDP6:[::1]:1,recvdstopts=0,ipv6-recvdstopts=1")
	if err != nil {
		t.Fatal(err)
	}
	if !NeedAncillary(lastOn) {
		t.Fatal("later ipv6-recvdstopts=1 must enable ReadMsg")
	}
	pathmtu, err := parse.ParseSpec("UDP6:[::1]:1,ipv6-recvpathmtu")
	if err != nil {
		t.Fatal(err)
	}
	if !NeedAncillary(pathmtu) {
		t.Fatal("bare ipv6-recvpathmtu must enable ReadMsg")
	}
}

func TestHandleIPv6ExtHdrAndPathMTUCmsg(t *testing.T) {
	g, buf := capturedAncillary(t)
	payload := []byte{0x3a, 0x00, 0x01, 0x02}
	handleIPv6Cmsg(unix.IPV6_DSTOPTS, payload, g)
	if g.SessionVars["IPV6_DSTOPTS"] != "" || g.SessionVars["DSTOPTS"] != "" {
		t.Fatalf("must not invent session env for extension headers: %v", g.SessionVars)
	}
	if !strings.Contains(buf.String(), "IPV6_DSTOPTS") || !strings.Contains(buf.String(), "dstopts=x3a000102") {
		t.Fatalf("dstopts log=%q", buf.String())
	}

	g, buf = capturedAncillary(t)
	handleIPv6Cmsg(unix.IPV6_HOPOPTS, []byte{0x0a, 0x0b}, g)
	if !strings.Contains(buf.String(), "IPV6_HOPOPTS") || !strings.Contains(buf.String(), "hopopts=x0a0b") {
		t.Fatalf("hopopts log=%q", buf.String())
	}

	g, buf = capturedAncillary(t)
	handleIPv6Cmsg(unix.IPV6_RTHDR, []byte{0xff}, g)
	if !strings.Contains(buf.String(), "IPV6_RTHDR") || !strings.Contains(buf.String(), "rthdr=xff") {
		t.Fatalf("rthdr log=%q", buf.String())
	}

	g, buf = capturedAncillary(t)
	handleIPv6Cmsg(unix.IPV6_PATHMTU, []byte{0x05, 0x00}, g)
	wantType := fmt.Sprintf("IPV6.%d", unix.IPV6_PATHMTU)
	if !strings.Contains(buf.String(), wantType) || !strings.Contains(buf.String(), "data=x0500") {
		t.Fatalf("pathmtu log=%q want type %s", buf.String(), wantType)
	}
	if len(g.SessionVars) != 0 {
		t.Fatalf("PATHMTU must not invent session env: %v", g.SessionVars)
	}
}

func TestProcessAncillaryIPv6ExtHdrCmsg(t *testing.T) {
	g, buf := capturedAncillary(t)
	oob := marshalIPv6Cmsg(t, unix.IPV6_DSTOPTS, []byte{0x11, 0x22})
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Header.Type != unix.IPV6_DSTOPTS {
		t.Fatalf("parsed %#v", msgs)
	}
	ProcessAncillary(oob, g)
	if !strings.Contains(buf.String(), "dstopts=x1122") {
		t.Fatalf("ProcessAncillary log=%q", buf.String())
	}

	g, buf = capturedAncillary(t)
	ProcessAncillary(marshalIPv6Cmsg(t, unix.IPV6_PATHMTU, []byte{0x00}), g)
	if !strings.Contains(buf.String(), "data=x00") {
		t.Fatalf("PATHMTU ProcessAncillary log=%q", buf.String())
	}
}

func capturedAncillary(t *testing.T) (*Global, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&buf)
	lg.SetLevel(logx.Info)
	return &Global{Log: lg}, &buf
}

func marshalIPv6Cmsg(t *testing.T, typ int32, data []byte) []byte {
	t.Helper()
	buf := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = int32(unix.IPPROTO_IPV6)
	h.Type = typ
	h.SetLen(unix.CmsgLen(len(data)))
	copy(buf[unix.CmsgLen(0):unix.CmsgLen(0)+len(data)], data)
	return buf
}
