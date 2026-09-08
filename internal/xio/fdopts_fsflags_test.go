package xio

import (
	"testing"
)

func TestApplyFSFlagMaskPreservesUnrelatedBits(t *testing.T) {
	const other = 0x00000100 // FS_DIRTY_FL, never requested
	got := applyFSFlagMask(other, fsNodumpFL, true)
	if got&other == 0 {
		t.Fatalf("cleared unrelated bits: %#x", got)
	}
	if got&fsNodumpFL == 0 {
		t.Fatalf("did not set FS_NODUMP_FL: %#x", got)
	}
	got = applyFSFlagMask(got, fsNodumpFL, false)
	if got != other {
		t.Fatalf("clear nodump: %#x want %#x", got, other)
	}
}

func TestLinuxExtFSFlagZeroClearsRequestedBitOnly(t *testing.T) {
	val := fsNodumpFL | fsNoatimeFL
	val = applyFSFlagMask(val, fsNodumpFL, false)
	if val&fsNodumpFL != 0 {
		t.Fatalf("nodump still set: %#x", val)
	}
	if val&fsNoatimeFL == 0 {
		t.Fatalf("cleared noatime: %#x", val)
	}
}
