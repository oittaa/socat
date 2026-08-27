//go:build windows

package xio

import (
	"io/fs"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestTransientLockCreateErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "access denied",
			err:  &os.PathError{Op: "open", Path: "lock", Err: syscall.ERROR_ACCESS_DENIED},
			want: true,
		},
		{
			name: "sharing violation",
			err:  &os.PathError{Op: "open", Path: "lock", Err: windows.ERROR_SHARING_VIOLATION},
			want: true,
		},
		{name: "already exists", err: fs.ErrExist},
		{name: "not found", err: fs.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientLockCreateError(tc.err); got != tc.want {
				t.Fatalf("isTransientLockCreateError(%v)=%v want %v", tc.err, got, tc.want)
			}
		})
	}
}
