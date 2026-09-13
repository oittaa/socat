package xio

import "testing"

func TestOptionsZeroValueDoesNotWrite(t *testing.T) {
	g := &Global{}
	if got := g.Options(); got != (Options{}) {
		t.Fatalf("Options=%+v", got)
	}
	if g.options != nil {
		t.Fatal("Options changed the zero session")
	}
}

func TestForkSessionZeroValueDoesNotWriteParentOptions(t *testing.T) {
	g := &Global{}
	child := g.ForkSession()
	if g.options != nil || g.statsPrinted != nil {
		t.Fatal("ForkSession changed parent options or stats")
	}
	if child.options == nil || child.Options() != (Options{}) {
		t.Fatal("child did not get zero options")
	}
}
