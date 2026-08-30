package relay

import (
	"testing"
	"time"
)

func TestIdleClockSharesOneSleeperAndBroadcasts(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{}, 2)
	clock := newIdleClock(func() {
		entered <- struct{}{}
		<-release
	})
	first := clock.subscribe()
	second := clock.subscribe()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("idle clock did not start")
	}
	select {
	case <-entered:
		t.Fatal("idle clock started more than one sleeper")
	default:
	}

	firstTick := first.next()
	secondTick := second.next()
	release <- struct{}{}
	for name, tick := range map[string]<-chan struct{}{"first": firstTick, "second": secondTick} {
		select {
		case <-tick:
		case <-time.After(time.Second):
			t.Fatalf("%s subscriber did not receive tick", name)
		}
	}

	first.close()
	second.close()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("idle clock did not enter its final sleep")
	}
	release <- struct{}{}

	deadline := time.Now().Add(time.Second)
	for {
		clock.mu.Lock()
		running, users := clock.running, clock.users
		clock.mu.Unlock()
		if !running && users == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("idle clock did not stop: running=%v users=%d", running, users)
		}
		time.Sleep(time.Millisecond)
	}
}
