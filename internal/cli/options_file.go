package cli

import (
	"fmt"
	"runtime"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// File, FD, and UNIX options.
func fileOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Files and UNIX", []helpOpt{
			// Windows-only; hidden and rejected off Windows. Applies
			// HANDLE_FLAG_INHERIT / text vs binary.
			{name: "binary", optionCaps: capOpenFD, desc: "use Windows binary descriptor mode", aliases: []string{"bin", "o-binary"}, validate: validateOptionalBool},
			{name: "text", optionCaps: capOpenFD, desc: "translate Windows CRLF text on descriptor I/O", aliases: []string{"o-text"}, validate: validateOptionalBool},
			{name: "noinherit", optionCaps: capOpenFD, desc: "clear Windows HANDLE_FLAG_INHERIT", aliases: []string{"o-noinherit"}, validate: validateOptionalBool},
			{name: "rdonly", optionCaps: capOpen, desc: "open read-only", aliases: []string{"o-rdonly", "o_rdonly"}},
			{name: "wronly", optionCaps: capOpen, desc: "open write-only", aliases: []string{"o-wronly", "o_wronly"}},
			{name: "rdwr", optionCaps: capOpen, desc: "open read-write", aliases: []string{"o-rdwr", "o_rdwr"}},
			{name: "creat", optionCaps: capOpen, desc: "create the file", aliases: []string{"create", "o-creat", "o-create", "o_creat", "o_create"}},
			{name: "excl", optionCaps: capOpen, desc: "fail if the file exists", aliases: []string{"o-excl", "o_excl"}},
			// Do not list address types: optionCaps intersection is authoritative.
			{name: "append", optionCaps: capOpenFD, desc: "open append or fcntl O_APPEND on an exposed fd", aliases: []string{"o-append"}},
			// cloexec=0 clears Go's default CLOEXEC only on an exposed
			// descriptor this process owns. Do not list address types.
			{name: "cloexec", optionCaps: capFD, desc: "fcntl FD_CLOEXEC on an exposed fd (cloexec=0 clears it)", validate: validateOptionalBool},
			{name: "trunc", optionCaps: capOpen, desc: "truncate on open", aliases: []string{"o-trunc"}},
			{name: "nonblock", optionCaps: capOpenFD, desc: "O_NONBLOCK", aliases: []string{"o-nonblock", "ndelay", "o-ndelay", "o_ndelay"}},
			// Do not list address types: optionCaps intersection is authoritative
			// (CREATE would wrongly get o-direct).
			{name: "o-direct", optionCaps: capOpen, desc: "set O_DIRECT at open", aliases: []string{"direct", "o_direct"}},
			{name: "o-sync", optionCaps: capOpen, desc: "set O_SYNC at open", aliases: []string{"sync", "o_sync"}},
			{name: "o-dsync", optionCaps: capOpen, desc: "set O_DSYNC at open", aliases: []string{"dsync", "o_dsync"}},
			{name: "o-rsync", optionCaps: capOpen, desc: "set O_RSYNC at open", aliases: []string{"rsync", "o_rsync"}},
			{name: "o-noctty", optionCaps: capOpen, desc: "set O_NOCTTY at open", aliases: []string{"noctty", "o_noctty"}},
			{name: "o-nofollow", optionCaps: capOpen, desc: "set O_NOFOLLOW at open", aliases: []string{"nofollow", "o_nofollow"}},
			{name: "o-directory", optionCaps: capOpen, desc: "set O_DIRECTORY at open", aliases: []string{"directory", "o_directory"}},
			{name: "o-largefile", optionCaps: capOpen, desc: "set O_LARGEFILE at open", aliases: []string{"largefile", "o_largefile"}},
			// fcntl O_ASYNC; named OPEN also ORs O_ASYNC into open(2).
			{name: "async", optionCaps: capOpenFD, desc: "fcntl O_ASYNC on the descriptor", aliases: []string{"o-async"}},
			{name: "o-noatime", optionCaps: capOpenFD, desc: "set O_NOATIME on the opened descriptor", aliases: []string{"noatime"}, addressTypes: fdOptionAddressTypes()},
			// fs-* are FS_*_FL ioctls, not open(2) flags. Do not list PIPE/EXEC.
			// fs-append is FS_APPEND_FL, not O_APPEND.
			{name: "fs-append", optionCaps: capREG, desc: "set FS_APPEND_FL on the file (not O_APPEND)", aliases: []string{"ext2-append", "ext3-append"}, validate: validateOptionalBool},
			{name: "fs-compr", optionCaps: capREG, desc: "set FS_COMPR_FL on the file", aliases: []string{"compr", "ext2-compr", "ext3-compr"}, validate: validateOptionalBool},
			{name: "fs-dirsync", optionCaps: capREG, desc: "set FS_DIRSYNC_FL on the file", aliases: []string{"dirsync", "ext2-dirsync", "ext3-dirsync"}, validate: validateOptionalBool},
			{name: "fs-immutable", optionCaps: capREG, desc: "set FS_IMMUTABLE_FL on the file", aliases: []string{"immutable", "ext2-immutable", "ext3-immutable"}, validate: validateOptionalBool},
			{name: "fs-journal-data", optionCaps: capREG, desc: "set FS_JOURNAL_DATA_FL on the file", aliases: []string{"journal", "journal-data", "ext2-journal-data", "ext3-journal-data"}, validate: validateOptionalBool},
			{name: "fs-noatime", optionCaps: capREG, desc: "set FS_NOATIME_FL on the file", aliases: []string{"ext2-noatime", "ext3-noatime"}, validate: validateOptionalBool},
			{name: "fs-nodump", optionCaps: capREG, desc: "set FS_NODUMP_FL on the file", aliases: []string{"nodump", "ext2-nodump", "ext3-nodump"}, validate: validateOptionalBool},
			{name: "fs-notail", optionCaps: capREG, desc: "set FS_NOTAIL_FL on the file", aliases: []string{"notail", "ext2-notail", "ext3-notail"}, validate: validateOptionalBool},
			{name: "fs-secrm", optionCaps: capREG, desc: "set FS_SECRM_FL on the file", aliases: []string{"secrm", "ext2-secrm", "ext3-secrm"}, validate: validateOptionalBool},
			{name: "fs-sync", optionCaps: capREG, desc: "set FS_SYNC_FL on the file (not O_SYNC)", aliases: []string{"ext2-sync", "ext3-sync"}, validate: validateOptionalBool},
			{name: "fs-topdir", optionCaps: capREG, desc: "set FS_TOPDIR_FL on the file", aliases: []string{"topdir", "ext2-topdir", "ext3-topdir"}, validate: validateOptionalBool},
			{name: "fs-unrm", optionCaps: capREG, desc: "set FS_UNRM_FL on the file", aliases: []string{"unrm", "ext2-unrm", "ext3-unrm"}, validate: validateOptionalBool},
			{name: "f-setpipe-sz", optionCaps: capFIFO, desc: "set Linux pipe capacity", aliases: []string{"pipesz"}, addressTypes: fdOptionAddressTypes(), validate: validateInteger(1)},
			{name: "perm", optionCaps: capFDNamed, desc: "chmod after open or on an exposed fd", aliases: []string{"mode"}, validate: validateOctal(0o7777)},
			{name: "perm-late", optionCaps: capFD, desc: "fchmod after perm/user/group", validate: validateOctal(0o7777)},
			{name: "perm-early", optionCaps: capNamed, desc: "chmod existing name before open, or UNIX socket after bind", validate: validateOctal(0o7777)},
			{name: "ftruncate", optionCaps: capREG, desc: "ftruncate(2) an opened regular file to this length", aliases: []string{"truncate", "ftruncate32", "ftruncate64"}, validate: validateInteger(0)},
			{name: "lseek", optionCaps: capRegBlk, desc: "lseek SEEK_SET on a regular file or block device", aliases: []string{"lseek64", "lseek64-set", "seek", "seek-set", "lseek32", "lseek32-set"}, validate: validateOptionalInt64},
			{name: "seek-cur", optionCaps: capRegBlk, desc: "lseek SEEK_CUR on a regular file or block device", aliases: []string{"lseek64-cur", "lseek32-cur"}, validate: validateOptionalInt64},
			{name: "seek-end", optionCaps: capRegBlk, desc: "lseek SEEK_END on a regular file or block device", aliases: []string{"lseek64-end", "lseek32-end"}, validate: validateOptionalInt64},
			{name: "setlk", optionCaps: capFD, desc: "nonblocking whole-file write lock", aliases: []string{"f-setlk-wr", "f-setlk", "setlk-wr"}},
			{name: "setlkw", optionCaps: capFD, desc: "blocking whole-file write lock", aliases: []string{"f-setlkw-wr", "f-setlkw", "lock", "lockw", "setlkw-wr"}},
			{name: "setlk-rd", optionCaps: capFD, desc: "nonblocking whole-file read lock", aliases: []string{"f-setlk-rd"}},
			{name: "setlkw-rd", optionCaps: capFD, desc: "blocking whole-file read lock", aliases: []string{"f-setlkw-rd"}},
			{name: "flock", optionCaps: capFD, desc: "exclusive flock(2) lock", aliases: []string{"flock-ex"}},
			{name: "flock-nb", optionCaps: capFD, desc: "nonblocking exclusive flock(2) lock", aliases: []string{"flock-ex-nb"}},
			{name: "flock-sh", optionCaps: capFD, desc: "shared flock(2) lock"},
			{name: "flock-sh-nb", optionCaps: capFD, desc: "nonblocking shared flock(2) lock"},
			// Do not list address types: optionCaps intersection is authoritative.
			// ioctl is an alias of ioctl-void.
			{name: "ioctl-void", optionCaps: capFD, desc: "ioctl() with request and NULL as the third argument", aliases: []string{"ioctl"}, validate: xio.ValidateGenericIoctl},
			{name: "ioctl-int", optionCaps: capFD, desc: "ioctl() with request and integer value", validate: xio.ValidateGenericIoctl},
			{name: "ioctl-intp", optionCaps: capFD, desc: "ioctl() with request and pointer to integer", validate: xio.ValidateGenericIoctl},
			{name: "ioctl-bin", optionCaps: capFD, desc: "ioctl() with request and pointer to dalan bytes", validate: xio.ValidateGenericIoctl},
			{name: "ioctl-string", optionCaps: capFD, desc: "ioctl() with request and pointer to C string (not dalan)", validate: xio.ValidateGenericIoctl},
			{name: "umask", unrestricted: true, desc: "umask during open or EXEC start", validate: validateOctal(0o777)},
			{name: "user", optionCaps: capFDNamed, desc: "file owner", aliases: []string{"uid", "owner"}, validate: validateRequiredString},
			{name: "group", optionCaps: capFDNamed, desc: "file group", aliases: []string{"gid"}, validate: validateRequiredString},
			{name: "user-late", optionCaps: capFD, desc: "fchown user after user/group", aliases: []string{"uid-l"}, validate: validateRequiredString},
			{name: "group-late", optionCaps: capFD, desc: "fchown group after user/group", aliases: []string{"gid-l"}, validate: validateRequiredString},
			{name: "user-early", optionCaps: capNamed, desc: "chown existing name before open, or UNIX socket after bind", aliases: []string{"uid-e"}, validate: validateRequiredString},
			{name: "group-early", optionCaps: capNamed, desc: "chgrp existing name before open, or UNIX socket after bind", aliases: []string{"gid-e"}, validate: validateRequiredString},
			{name: "unlink-early", optionCaps: capNamed, desc: "unlink before bind/open", aliases: []string{"new"}},
			{name: "unlink", optionCaps: capNamed, desc: "unlink before open", aliases: []string{"delete", "remove"}},
			{name: "unlink-close", optionCaps: capNamed, desc: "unlink on close"},
			{name: "unlink-late", optionCaps: capNamed, desc: "unlink immediately after open"},
			{name: "unix-bind-tempname", optionCaps: capSockUNIX, desc: "bind a temporary UNIX name", aliases: []string{"bind-tempname"}},
			{name: "unix-tightsocklen", optionCaps: capSockUNIX, desc: "use a tight sockaddr_un length", aliases: []string{"tightsocklen"}, validate: validateUnixTightSocklen},
			{name: "socktype", optionCaps: capSocket, dynamicDesc: xio.UnixSocktypeHelp, aliases: []string{"so-type", "type"}, validate: validateInteger(-1)},
		}},
	}
}

func validateUnixTightSocklen(option parse.Option) error {
	if err := validateOptionalBool(option); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("%s: not supported on this platform", option.Name)
	}
	return nil
}
