package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestWritePayloadMatchesBenchmarkStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload")
	if err := writePayload(path, 1024*1024); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(data)
	want, err := hex.DecodeString("925f959b52e80db3cfe583ac121e664503ffa806c9fc1626de8dd16fa54e2648")
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:]) != string(want) {
		t.Fatalf("payload hash=%x", got)
	}
}
