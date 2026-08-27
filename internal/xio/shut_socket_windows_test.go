//go:build windows

package xio

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsNotSockMatchesWSAENOTSOCK(t *testing.T) {
	if !isNotSock(windows.WSAENOTSOCK) {
		t.Fatal("windows.WSAENOTSOCK must satisfy isNotSock")
	}
	if !isNotSock(fmt.Errorf("shut-down: %w", windows.WSAENOTSOCK)) {
		t.Fatal("wrapped WSAENOTSOCK must satisfy isNotSock")
	}
}
