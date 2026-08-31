//go:build linux || darwin

package main

import "time"

type benchmarkInstant = time.Time

func benchmarkNow() benchmarkInstant {
	return time.Now()
}

func benchmarkSince(start benchmarkInstant) time.Duration {
	return time.Since(start)
}
