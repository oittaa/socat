package xio

import (
	"sync"
	"testing"
)

// TestOptionsZeroValueDoesNotWrite fails if Options() lazily writes
// g.options. Concurrent read-only calls on a zero Global then race and
// can return distinct backing objects.
func TestOptionsZeroValueDoesNotWrite(t *testing.T) {
	g := &Global{}
	const n = 16
	var ready, done sync.WaitGroup
	ready.Add(n)
	done.Add(n)
	start := make(chan struct{})
	got := make([]Options, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start
			got[i] = g.Options()
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()
	if g.options != nil {
		t.Fatal("Options() must not allocate on a zero session")
	}
	var zero Options
	for i, o := range got {
		if o != zero {
			t.Fatalf("goroutine %d got %+v", i, o)
		}
	}
}

func TestForkSessionZeroValueDoesNotWriteParentOptions(t *testing.T) {
	g := &Global{}
	const n = 16
	var ready, done sync.WaitGroup
	ready.Add(n)
	done.Add(n)
	start := make(chan struct{})
	children := make([]*Global, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start
			_ = g.Options()
			children[i] = g.ForkSession()
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()
	if g.options != nil || g.statsPrinted != nil {
		t.Fatal("ForkSession must not write options or stats on a zero parent")
	}
	for i, c := range children {
		if c == nil || c.options == nil {
			t.Fatalf("child %d missing options", i)
		}
		if c.sharesOptions(g) {
			t.Fatal("zero parent must not share options storage")
		}
	}
}
