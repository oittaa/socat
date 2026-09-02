//go:build linux || darwin

package filan

import (
	"bytes"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/outbuf"
)

func TestWriteHeaderTabSeparatedColumns(t *testing.T) {
	var b outbuf.Buf
	var buf bytes.Buffer
	WriteHeader(&b)
	if err := b.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	header := strings.TrimSuffix(buf.String(), "\n")
	cols := strings.Split(header, "\t")
	want := []string{
		"  FD  type", "device", "inode", "mode", "links", "uid", "gid", "rdev",
		"size", "blksize", "blocks", "atime", "mtime", "ctime", "cloexec", "flags", "sigown",
	}
	if runtime.GOOS == "linux" {
		want = append(want, "sigio")
	}
	if !reflect.DeepEqual(cols, want) {
		t.Fatalf("header cols=%q want %q", cols, want)
	}
}

func TestWriteFDPlacesTimesAfterBlksizeAndBlocks(t *testing.T) {
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	var b outbuf.Buf
	var buf bytes.Buffer
	WriteFD(&b, int(f.Fd()), Options{})
	if err := b.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(buf.String(), "\n")
	fields := strings.Split(line, "\t")
	if len(fields) < 17 {
		t.Fatalf("too few columns: %q", fields)
	}
	if fields[8] != "0" {
		t.Fatalf("size=%q want 0", fields[8])
	}
	if _, err := strconv.Atoi(fields[9]); err != nil {
		t.Fatalf("blksize=%q", fields[9])
	}
	if _, err := strconv.Atoi(fields[10]); err != nil {
		t.Fatalf("blocks=%q", fields[10])
	}
	iso := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`)
	for _, i := range []int{11, 12, 13} {
		if !iso.MatchString(fields[i]) {
			t.Fatalf("time field %d = %q", i, fields[i])
		}
	}
	if runtime.GOOS != "linux" {
		return
	}
	if len(fields) < 18 {
		t.Fatalf("missing sigio: %q", fields)
	}
	if _, err := strconv.Atoi(fields[17]); err != nil {
		t.Fatalf("sigio=%q", fields[17])
	}
}
