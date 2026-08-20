package relay

import "testing"

func TestConfiguredBlockCount(t *testing.T) {
	tests := []struct {
		name       string
		n          int64
		bufferSize int
		want       uint64
	}{
		{name: "negative bytes", n: -1, bufferSize: 8192, want: 0},
		{name: "zero bytes", n: 0, bufferSize: 8192, want: 0},
		{name: "zero buffer", n: 1, bufferSize: 0, want: 0},
		{name: "negative buffer", n: 1, bufferSize: -1, want: 0},
		{name: "partial block", n: 1, bufferSize: 8192, want: 1},
		{name: "exact blocks", n: 16384, bufferSize: 8192, want: 2},
		{name: "rounded up", n: 16385, bufferSize: 8192, want: 3},
		{name: "large count", n: 9223372036854775807, bufferSize: 8192, want: 1125899906842624},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configuredBlockCount(tt.n, tt.bufferSize); got != tt.want {
				t.Fatalf("configuredBlockCount(%d, %d) = %d, want %d", tt.n, tt.bufferSize, got, tt.want)
			}
		})
	}
}
