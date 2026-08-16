package xio

import "math"

// Uint8FromInt converts n to uint8 when it fits (SOCKS length prefixes).
func Uint8FromInt(n int) (uint8, bool) {
	if n < 0 || n > math.MaxUint8 {
		return 0, false
	}
	return uint8(n), true
}

// Uint16FromInt converts n to uint16 when it fits (TCP/UDP ports).
func Uint16FromInt(n int) (uint16, bool) {
	if n < 0 || n > math.MaxUint16 {
		return 0, false
	}
	return uint16(n), true
}

// Uint32FromInt converts n to uint32 when it fits (interface index).
func Uint32FromInt(n int) (uint32, bool) {
	if n < 0 || uint64(n) > math.MaxUint32 {
		return 0, false
	}
	return uint32(n), true
}

// Int32FromUint32 converts u to int32 when it fits (kernel int fields).
func Int32FromUint32(u uint32) (int32, bool) {
	if u > uint32(math.MaxInt32) {
		return 0, false
	}
	return int32(u), true
}

// Int64FromUint64 converts u to int64 when it fits (kernel 64-bit fields).
func Int64FromUint64(u uint64) (int64, bool) {
	if u > uint64(math.MaxInt64) {
		return 0, false
	}
	return int64(u), true
}
