package relay

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
)

type boolTimeout struct {
	error
	timeout bool
}

func (e boolTimeout) Timeout() bool { return e.timeout }

func TestIsTimeoutErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "deadline-exceeded", err: os.ErrDeadlineExceeded, want: true},
		{name: "context-deadline", err: context.DeadlineExceeded, want: true},
		{name: "os-timeout", err: os.ErrDeadlineExceeded, want: true},
		{
			name: "wrapped-timeout-bool",
			err:  fmt.Errorf("wrap: %w", boolTimeout{error: errors.New("slow"), timeout: true}),
			want: true,
		},
		{
			name: "non-net-timeout-type",
			err:  boolTimeout{error: errors.New("slow"), timeout: true},
			want: true,
		},
		{
			name: "timeout-false",
			err:  boolTimeout{error: errors.New("other"), timeout: false},
			want: false,
		},
		{name: "plain", err: errors.New("nope"), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTimeoutErr(tc.err); got != tc.want {
				t.Fatalf("IsTimeoutErr(%v)=%v want %v", tc.err, got, tc.want)
			}
		})
	}
}
