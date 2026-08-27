package xio

import (
	"reflect"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestLinuxExtFSFlagSpellingCanonicalMask(t *testing.T) {
	tests := []struct {
		spelling, canonical string
		mask                int
		fsFlag              bool
	}{
		{"fs-append", "fs-append", fsAppendFL, true},
		{"ext2-append", "fs-append", fsAppendFL, true},
		{"ext3-append", "fs-append", fsAppendFL, true},
		{"fs-compr", "fs-compr", fsComprFL, true},
		{"compr", "fs-compr", fsComprFL, true},
		{"ext2-compr", "fs-compr", fsComprFL, true},
		{"ext3-compr", "fs-compr", fsComprFL, true},
		{"fs-dirsync", "fs-dirsync", fsDirsyncFL, true},
		{"dirsync", "fs-dirsync", fsDirsyncFL, true},
		{"ext2-dirsync", "fs-dirsync", fsDirsyncFL, true},
		{"ext3-dirsync", "fs-dirsync", fsDirsyncFL, true},
		{"fs-immutable", "fs-immutable", fsImmutableFL, true},
		{"immutable", "fs-immutable", fsImmutableFL, true},
		{"ext2-immutable", "fs-immutable", fsImmutableFL, true},
		{"ext3-immutable", "fs-immutable", fsImmutableFL, true},
		{"fs-journal-data", "fs-journal-data", fsJournalDataFL, true},
		{"journal", "fs-journal-data", fsJournalDataFL, true},
		{"journal-data", "fs-journal-data", fsJournalDataFL, true},
		{"ext2-journal-data", "fs-journal-data", fsJournalDataFL, true},
		{"ext3-journal-data", "fs-journal-data", fsJournalDataFL, true},
		{"fs-nodump", "fs-nodump", fsNodumpFL, true},
		{"nodump", "fs-nodump", fsNodumpFL, true},
		{"ext2-nodump", "fs-nodump", fsNodumpFL, true},
		{"ext3-nodump", "fs-nodump", fsNodumpFL, true},
		{"fs-notail", "fs-notail", fsNotailFL, true},
		{"notail", "fs-notail", fsNotailFL, true},
		{"ext2-notail", "fs-notail", fsNotailFL, true},
		{"ext3-notail", "fs-notail", fsNotailFL, true},
		{"fs-secrm", "fs-secrm", fsSecrmFL, true},
		{"secrm", "fs-secrm", fsSecrmFL, true},
		{"ext2-secrm", "fs-secrm", fsSecrmFL, true},
		{"ext3-secrm", "fs-secrm", fsSecrmFL, true},
		{"fs-sync", "fs-sync", fsSyncFL, true},
		{"ext2-sync", "fs-sync", fsSyncFL, true},
		{"ext3-sync", "fs-sync", fsSyncFL, true},
		{"fs-topdir", "fs-topdir", fsTopdirFL, true},
		{"topdir", "fs-topdir", fsTopdirFL, true},
		{"ext2-topdir", "fs-topdir", fsTopdirFL, true},
		{"ext3-topdir", "fs-topdir", fsTopdirFL, true},
		{"fs-unrm", "fs-unrm", fsUnrmFL, true},
		{"unrm", "fs-unrm", fsUnrmFL, true},
		{"ext2-unrm", "fs-unrm", fsUnrmFL, true},
		{"ext3-unrm", "fs-unrm", fsUnrmFL, true},
		{"fs-noatime", "fs-noatime", fsNoatimeFL, true},
		{"ext2-noatime", "fs-noatime", fsNoatimeFL, true},
		{"ext3-noatime", "fs-noatime", fsNoatimeFL, true},
		// Shadowed nicknames: classic optionnames[] maps these to open(2)/fcntl
		// flags, not FS_*_FL (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba).
		{"append", "append", 0, false},
		{"sync", "o-sync", 0, false},
		{"noatime", "noatime", 0, false},
	}
	for _, tc := range tests {
		gotCanon := parse.CanonicalOptionName(tc.spelling)
		if gotCanon != tc.canonical {
			t.Errorf("%s: canonical=%q want %q", tc.spelling, gotCanon, tc.canonical)
		}
		if LinuxExtFSFlagOption(tc.canonical) != tc.fsFlag {
			t.Errorf("%s: LinuxExtFSFlagOption(%q)=%v want %v", tc.spelling, tc.canonical, LinuxExtFSFlagOption(tc.canonical), tc.fsFlag)
		}
		if !tc.fsFlag {
			if _, ok := linuxExtFSFlagMasks[tc.spelling]; ok {
				t.Errorf("%s must not be a canonical FS_*_FL key", tc.spelling)
			}
			continue
		}
		if got := linuxExtFSFlagMasks[tc.canonical]; got != tc.mask {
			t.Errorf("%s: mask=%#x want %#x", tc.spelling, got, tc.mask)
		}
	}
}

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

func TestLinuxExtFSFlagOpsCommandLineOrderLastWins(t *testing.T) {
	spec, err := parse.ParseSpec("FD:3,fs-nodump,ext2-append,nodump=0,fs-noatime")
	if err != nil {
		t.Fatal(err)
	}
	got := linuxExtFSFlagOps(spec)
	want := []linuxExtFSFlagOp{
		{name: "fs-nodump", mask: fsNodumpFL, enable: true},
		{name: "fs-append", mask: fsAppendFL, enable: true},
		{name: "fs-nodump", mask: fsNodumpFL, enable: false},
		{name: "fs-noatime", mask: fsNoatimeFL, enable: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ops=%+v want %+v", got, want)
	}
	val := 0x00000100
	for _, op := range got {
		val = applyFSFlagMask(val, op.mask, op.enable)
	}
	if val&fsNodumpFL != 0 {
		t.Fatalf("last nodump=0 must win: %#x", val)
	}
	if val&fsAppendFL == 0 || val&fsNoatimeFL == 0 || val&0x00000100 == 0 {
		t.Fatalf("append/noatime/unrelated bits: %#x", val)
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
