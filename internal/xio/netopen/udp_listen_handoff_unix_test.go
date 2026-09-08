//go:build linux

package netopen

import "testing"

func TestUDPForkQueuesAreBounded(t *testing.T) {
	listener := &udpForkListener{}
	for i := 0; i < udpForkPendingQueueSize+10; i++ {
		listener.appendPending(udpForkPacket{data: []byte{byte(i)}})
	}
	if got := len(listener.pending); got != udpForkPendingQueueSize {
		t.Fatalf("pending queue length = %d, want %d", got, udpForkPendingQueueSize)
	}

	front := udpForkPacket{data: []byte("retry")}
	listener.prependPending(front)
	if got := len(listener.pending); got != udpForkPendingQueueSize {
		t.Fatalf("pending queue after prepend = %d, want %d", got, udpForkPendingQueueSize)
	}
	if got := string(listener.pending[0].data); got != "retry" {
		t.Fatalf("pending queue front = %q, want retry opener", got)
	}

	child := &udpSessionConn{}
	for i := 0; i < udpForkSessionQueueSize+10; i++ {
		appendUDPForkSessionPacket(child, udpForkPacket{data: []byte{byte(i)}})
	}
	if got := len(child.queued); got != udpForkSessionQueueSize {
		t.Fatalf("session queue length = %d, want %d", got, udpForkSessionQueueSize)
	}
}
