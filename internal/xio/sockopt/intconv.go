package sockopt

import "math"

func Uint32FromInt(n int) (uint32, bool) {
	if n < 0 || uint64(n) > math.MaxUint32 {
		return 0, false
	}
	return uint32(n), true
}

func int32FromUint32(u uint32) (int32, bool) {
	if u > uint32(math.MaxInt32) {
		return 0, false
	}
	return int32(u), true
}

func int64FromUint64(u uint64) (int64, bool) {
	if u > uint64(math.MaxInt64) {
		return 0, false
	}
	return int64(u), true
}
