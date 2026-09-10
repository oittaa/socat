//go:build e2e

package e2e

import (
	"errors"
	"testing"
)

func TestListenOwnerFromCIgnoresErrnoUnlessFailed(t *testing.T) {
	stale := errors.New("stale errno")
	ok, err := listenOwnerFromC(1, stale)
	if err != nil || !ok {
		t.Fatalf("listening: ok=%v err=%v", ok, err)
	}
	ok, err = listenOwnerFromC(0, stale)
	if err != nil || ok {
		t.Fatalf("not listening: ok=%v err=%v", ok, err)
	}
	ok, err = listenOwnerFromC(-1, stale)
	if ok || !errors.Is(err, stale) {
		t.Fatalf("alloc failure: ok=%v err=%v", ok, err)
	}
	ok, err = listenOwnerFromC(-1, nil)
	if ok || err == nil {
		t.Fatalf("alloc failure without errno: ok=%v err=%v", ok, err)
	}
}
