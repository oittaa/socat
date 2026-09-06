package dtls13

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestConnAbandonedCommandDoesNotAffectNextWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server, _ := syntheticConnectionPair(t)
		keys := client.session.write[client.session.currentWriteEpoch()].keys
		gate := &gatedOverheadAEAD{AEAD: keys.aead, entered: make(chan struct{}), release: make(chan struct{})}
		keys.aead = gate
		first := make(chan error, 1)
		go func() { _, err := client.Write([]byte("abandoned")); first <- err }()
		<-gate.entered
		if err := client.SetWriteDeadline(time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := <-first; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("abandoned write: %v", err)
		}
		if err := client.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		second := make(chan error, 1)
		go func() { _, err := client.Write([]byte("replacement")); second <- err }()
		synctest.Wait()
		close(gate.release)
		if err := <-second; err != nil {
			t.Fatalf("replacement write: %v", err)
		}
		if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 100)
		if n, err := server.Read(buffer); err != nil || string(buffer[:n]) != "replacement" {
			t.Fatalf("received %q, %v", buffer[:n], err)
		}
	})
}

func TestConnConcurrentWritesKeepDistinctCommands(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server, _ := syntheticConnectionPair(t)
		var group sync.WaitGroup
		for i := range 16 {
			group.Go(func() {
				if _, err := client.Write(bytes.Repeat([]byte{byte(i)}, 100)); err != nil {
					t.Error(err)
				}
			})
		}
		group.Wait()
		if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		seen := make(map[byte]bool)
		for range 16 {
			buffer := make([]byte, 200)
			n, err := server.Read(buffer)
			if err != nil || n != 100 || !bytes.Equal(buffer[:n], bytes.Repeat(buffer[:1], 100)) || seen[buffer[0]] {
				t.Fatalf("concurrent write corrupted or repeated: %q, %v", buffer[:n], err)
			}
			seen[buffer[0]] = true
		}
	})
}
