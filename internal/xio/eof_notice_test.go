package xio

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

type eofNoticeCloser struct{}

func (eofNoticeCloser) Close() error { return nil }

type eofNoticeEOF struct{}

func (eofNoticeEOF) Read([]byte) (int, error) { return 0, io.EOF }

type eofNoticeFD struct {
	relay.FDStream
	fd int
}

func (s eofNoticeFD) StreamProps() relay.Props {
	p := relay.NoProps()
	p.ReadFD = s.fd
	return p
}

func transferEOFNotice(t *testing.T, left, right relay.Stream) string {
	t.Helper()
	var logBuf bytes.Buffer
	lg := logx.New()
	lg.SetOutput(&logBuf)
	lg.SetLevel(logx.Notice)
	g := &Global{Log: lg, BlockSize: 8192, Linger: 0, LeftToRight: true}
	if err := transferStreamsOpts(context.Background(), left, right, g, false, false); err != nil {
		t.Fatal(err)
	}
	return logBuf.String()
}

func TestEOFNoticeUnknownFDIsNotZero(t *testing.T) {
	left := relay.FDStream{R: strings.NewReader("hi"), W: io.Discard, C: eofNoticeCloser{}}
	right := relay.FDStream{R: eofNoticeEOF{}, W: io.Discard, C: eofNoticeCloser{}}
	got := transferEOFNotice(t, left, right)
	if !strings.Contains(got, "is at EOF") {
		t.Fatalf("missing EOF notice:\n%s", got)
	}
	if strings.Contains(got, "(fd 0)") {
		t.Fatalf("unknown source FD reported as stdin fd 0:\n%s", got)
	}
}

func TestEOFNoticeReportsSourceReadFD(t *testing.T) {
	left := eofNoticeFD{FDStream: relay.FDStream{R: eofNoticeEOF{}, W: io.Discard, C: eofNoticeCloser{}}, fd: 7}
	right := relay.FDStream{R: eofNoticeEOF{}, W: io.Discard, C: eofNoticeCloser{}}
	got := transferEOFNotice(t, left, right)
	if !strings.Contains(got, "socket 1 (fd 7) is at EOF") {
		t.Fatalf("want source fd 7 in notice:\n%s", got)
	}
}

func TestEOFNoticeRealFDZeroIsPreserved(t *testing.T) {
	left := eofNoticeFD{FDStream: relay.FDStream{R: eofNoticeEOF{}, W: io.Discard, C: eofNoticeCloser{}}, fd: 0}
	right := relay.FDStream{R: eofNoticeEOF{}, W: io.Discard, C: eofNoticeCloser{}}
	got := transferEOFNotice(t, left, right)
	if !strings.Contains(got, "socket 1 (fd 0) is at EOF") {
		t.Fatalf("real fd 0 must still be reported:\n%s", got)
	}
}
