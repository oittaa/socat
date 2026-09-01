package netopen

import (
	"errors"
	"io"
	"testing"
)

func TestCopyOneshotFirst(t *testing.T) {
	t.Parallel()
	n, err := copyOneshotFirst(make([]byte, 8), nil)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty first n=%d err=%v want EOF", n, err)
	}
	buf := make([]byte, 8)
	n, err = copyOneshotFirst(buf, []byte("hi"))
	if err != nil || string(buf[:n]) != "hi" {
		t.Fatalf("payload n=%d err=%v data=%q", n, err, buf[:n])
	}
}
