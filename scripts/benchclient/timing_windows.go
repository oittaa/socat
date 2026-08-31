//go:build windows

package main

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type benchmarkInstant int64

var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	queryPerformanceCounter     = kernel32.NewProc("QueryPerformanceCounter")
	queryPerformanceFrequency   = kernel32.NewProc("QueryPerformanceFrequency")
	performanceCounterFrequency = readPerformanceCounterFrequency()
)

func readPerformanceCounterFrequency() int64 {
	var frequency int64
	// #nosec G103 -- QueryPerformanceFrequency requires an output pointer.
	ok, _, err := queryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&frequency)))
	if ok == 0 || frequency <= 0 {
		panic(fmt.Sprintf("QueryPerformanceFrequency: %v", err))
	}
	return frequency
}

func benchmarkNow() benchmarkInstant {
	var counter int64
	// #nosec G103 -- QueryPerformanceCounter requires an output pointer.
	ok, _, err := queryPerformanceCounter.Call(uintptr(unsafe.Pointer(&counter)))
	if ok == 0 {
		panic(fmt.Sprintf("QueryPerformanceCounter: %v", err))
	}
	return benchmarkInstant(counter)
}

func benchmarkSince(start benchmarkInstant) time.Duration {
	delta := int64(benchmarkNow() - start)
	seconds := delta / performanceCounterFrequency
	remainder := delta % performanceCounterFrequency
	return time.Duration(seconds)*time.Second +
		time.Duration(remainder)*time.Second/time.Duration(performanceCounterFrequency)
}
