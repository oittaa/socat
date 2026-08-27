package cli

import "github.com/oittaa/socat/internal/xio"

// File, FD, and UNIX options.
func fileOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Files and UNIX", []helpOpt{
			{name: "rdonly", desc: "open read-only", aliases: []string{"o-rdonly", "o_rdonly"}},
			{name: "wronly", desc: "open write-only", aliases: []string{"o-wronly", "o_wronly"}},
			{name: "rdwr", desc: "open read-write", aliases: []string{"o-rdwr", "o_rdwr"}},
			{name: "creat", desc: "create the file", aliases: []string{"create", "o-creat", "o-create", "o_creat", "o_create"}},
			{name: "excl", desc: "fail if the file exists", aliases: []string{"o-excl", "o_excl"}},
			// GROUP_FD|GROUP_OPEN (xio-fd.c). Do not list address types:
			// classic group intersection allows FD/STDIO/EXEC/sockets and
			// rejects combinations that lack those groups.
			{name: "append", desc: "open append or fcntl O_APPEND on an exposed fd", aliases: []string{"o-append"}},
			{name: "trunc", desc: "truncate on open", aliases: []string{"o-trunc"}},
			{name: "nonblock", desc: "O_NONBLOCK", aliases: []string{"o-nonblock", "ndelay", "o-ndelay", "o_ndelay"}},
			// GROUP_OPEN only (xio-file.c). A FILE/OPEN type list would widen
			// to CREATE, which classic rejects; intersection is authoritative.
			{name: "o-direct", desc: "set O_DIRECT at open", aliases: []string{"direct", "o_direct"}},
			{name: "o-sync", desc: "set O_SYNC at open", aliases: []string{"sync", "o_sync"}},
			{name: "o-dsync", desc: "set O_DSYNC at open", aliases: []string{"dsync", "o_dsync"}},
			{name: "o-rsync", desc: "set O_RSYNC at open", aliases: []string{"rsync", "o_rsync"}},
			{name: "o-noctty", desc: "set O_NOCTTY at open", aliases: []string{"noctty", "o_noctty"}},
			{name: "o-nofollow", desc: "set O_NOFOLLOW at open", aliases: []string{"nofollow", "o_nofollow"}},
			{name: "o-directory", desc: "set O_DIRECTORY at open", aliases: []string{"directory", "o_directory"}},
			{name: "o-largefile", desc: "set O_LARGEFILE at open", aliases: []string{"largefile", "o_largefile"}},
			// GROUP_OPEN|GROUP_FD, PH_LATE OFUNC_FCNTL (xio-fd.c). Named OPEN
			// also ORs O_ASYNC into open(2) like classic _xioopen_open.
			{name: "async", desc: "fcntl O_ASYNC on the descriptor", aliases: []string{"o-async"}},
			{name: "o-noatime", desc: "set O_NOATIME on the opened descriptor", aliases: []string{"noatime"}, addressTypes: fdOptionAddressTypes()},
			// GROUP_REG only (xio-fs.c OFUNC_IOCTL_MASK_LONG). Classic
			// tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
			// official master af5388c898c7bb60997935aee93c223deba60c4a.
			// fdOptionAddressTypes would widen to PIPE/EXEC, which
			// classic rejects; intersection is authoritative.
			// fs-append is FS_APPEND_FL, not open(2) O_APPEND.
			{name: "fs-append", desc: "set FS_APPEND_FL on the file (not O_APPEND)", aliases: []string{"ext2-append", "ext3-append"}, validate: validateOptionalBool},
			{name: "fs-compr", desc: "set FS_COMPR_FL on the file", aliases: []string{"compr", "ext2-compr", "ext3-compr"}, validate: validateOptionalBool},
			{name: "fs-dirsync", desc: "set FS_DIRSYNC_FL on the file", aliases: []string{"dirsync", "ext2-dirsync", "ext3-dirsync"}, validate: validateOptionalBool},
			{name: "fs-immutable", desc: "set FS_IMMUTABLE_FL on the file", aliases: []string{"immutable", "ext2-immutable", "ext3-immutable"}, validate: validateOptionalBool},
			{name: "fs-journal-data", desc: "set FS_JOURNAL_DATA_FL on the file", aliases: []string{"journal", "journal-data", "ext2-journal-data", "ext3-journal-data"}, validate: validateOptionalBool},
			{name: "fs-noatime", desc: "set FS_NOATIME_FL on the file", aliases: []string{"ext2-noatime", "ext3-noatime"}, validate: validateOptionalBool},
			{name: "fs-nodump", desc: "set FS_NODUMP_FL on the file", aliases: []string{"nodump", "ext2-nodump", "ext3-nodump"}, validate: validateOptionalBool},
			{name: "fs-notail", desc: "set FS_NOTAIL_FL on the file", aliases: []string{"notail", "ext2-notail", "ext3-notail"}, validate: validateOptionalBool},
			{name: "fs-secrm", desc: "set FS_SECRM_FL on the file", aliases: []string{"secrm", "ext2-secrm", "ext3-secrm"}, validate: validateOptionalBool},
			{name: "fs-sync", desc: "set FS_SYNC_FL on the file (not O_SYNC)", aliases: []string{"ext2-sync", "ext3-sync"}, validate: validateOptionalBool},
			{name: "fs-topdir", desc: "set FS_TOPDIR_FL on the file", aliases: []string{"topdir", "ext2-topdir", "ext3-topdir"}, validate: validateOptionalBool},
			{name: "fs-unrm", desc: "set FS_UNRM_FL on the file", aliases: []string{"unrm", "ext2-unrm", "ext3-unrm"}, validate: validateOptionalBool},
			{name: "f-setpipe-sz", desc: "set Linux pipe capacity", aliases: []string{"pipesz"}, addressTypes: fdOptionAddressTypes(), validate: validateInteger(1)},
			{name: "perm", desc: "chmod after open or on an exposed fd (classic TYPE_MODET)", aliases: []string{"mode"}, validate: validateOctal(0o7777)},
			{name: "perm-late", desc: "fchmod at classic PH_LATE, after PH_FD perm/user/group", validate: validateOctal(0o7777)},
			{name: "perm-early", desc: "chmod existing name before open, or UNIX socket after bind", validate: validateOctal(0o7777)},
			{name: "ftruncate", desc: "ftruncate(2) an opened regular file to this length", aliases: []string{"truncate", "ftruncate32", "ftruncate64"}, validate: validateInteger(0)},
			{name: "lseek", desc: "lseek SEEK_SET on a regular file or block device", aliases: []string{"lseek64", "lseek64-set", "seek", "seek-set", "lseek32", "lseek32-set"}, validate: validateOptionalInt64},
			{name: "seek-cur", desc: "lseek SEEK_CUR on a regular file or block device", aliases: []string{"lseek64-cur", "lseek32-cur"}, validate: validateOptionalInt64},
			{name: "seek-end", desc: "lseek SEEK_END on a regular file or block device", aliases: []string{"lseek64-end", "lseek32-end"}, validate: validateOptionalInt64},
			{name: "setlk", desc: "nonblocking whole-file write lock", aliases: []string{"f-setlk-wr", "f-setlk", "setlk-wr"}},
			{name: "setlkw", desc: "blocking whole-file write lock", aliases: []string{"f-setlkw-wr", "f-setlkw", "lock", "lockw", "setlkw-wr"}},
			{name: "setlk-rd", desc: "nonblocking whole-file read lock", aliases: []string{"f-setlk-rd"}},
			{name: "setlkw-rd", desc: "blocking whole-file read lock", aliases: []string{"f-setlkw-rd"}},
			{name: "flock", desc: "exclusive flock(2) lock (classic PH_FD)", aliases: []string{"flock-ex"}},
			{name: "flock-nb", desc: "nonblocking exclusive flock(2) lock", aliases: []string{"flock-ex-nb"}},
			{name: "flock-sh", desc: "shared flock(2) lock"},
			{name: "flock-sh-nb", desc: "nonblocking shared flock(2) lock"},
			{name: "umask", desc: "umask during open or EXEC start", validate: validateOctal(0o777)},
			{name: "user", desc: "file owner", aliases: []string{"uid", "owner"}, validate: validateRequiredString},
			{name: "group", desc: "file group", aliases: []string{"gid"}, validate: validateRequiredString},
			{name: "user-late", desc: "fchown user at classic PH_LATE, after PH_FD user/group", aliases: []string{"uid-l"}, validate: validateRequiredString},
			{name: "group-late", desc: "fchown group at classic PH_LATE, after PH_FD user/group", aliases: []string{"gid-l"}, validate: validateRequiredString},
			{name: "user-early", desc: "chown existing name before open, or UNIX socket after bind", aliases: []string{"uid-e"}, validate: validateRequiredString},
			{name: "group-early", desc: "chgrp existing name before open, or UNIX socket after bind", aliases: []string{"gid-e"}, validate: validateRequiredString},
			{name: "unlink-early", desc: "unlink before bind/open", aliases: []string{"new"}},
			{name: "unlink", desc: "unlink before open", aliases: []string{"delete", "remove"}},
			{name: "unlink-close", desc: "unlink on close"},
			{name: "unlink-late", desc: "unlink immediately after open"},
			{name: "unix-bind-tempname", desc: "bind a temporary UNIX name", aliases: []string{"bind-tempname"}},
			{name: "socktype", dynamicDesc: xio.UnixSocktypeHelp, aliases: []string{"so-type", "type"}, validate: validateInteger(-1)},
		}},
	}
}
