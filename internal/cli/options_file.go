package cli

import "github.com/oittaa/socat/internal/xio"

// File, FD, and UNIX options.
func fileOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Files and UNIX", []helpOpt{
			{name: "rdonly", desc: "open read-only"},
			{name: "wronly", desc: "open write-only"},
			{name: "creat", desc: "create the file", aliases: []string{"create"}},
			{name: "excl", desc: "fail if the file exists"},
			// GROUP_FD|GROUP_OPEN (xio-fd.c). Do not list address types:
			// classic group intersection allows FD/STDIO/EXEC/sockets and
			// rejects combinations that lack those groups.
			{name: "append", desc: "open append or fcntl O_APPEND on an exposed fd", aliases: []string{"o-append"}},
			{name: "trunc", desc: "truncate on open"},
			{name: "nonblock", desc: "O_NONBLOCK", aliases: []string{"o-nonblock"}},
			// GROUP_OPEN only (xio-file.c). A FILE/OPEN type list would widen
			// to CREATE, which classic rejects; intersection is authoritative.
			{name: "o-direct", desc: "set O_DIRECT at open", aliases: []string{"direct", "o_direct"}},
			{name: "o-noatime", desc: "set O_NOATIME on the opened descriptor", aliases: []string{"noatime"}, addressTypes: fdOptionAddressTypes()},
			// GROUP_REG only (xio-fs.c). fdOptionAddressTypes would widen to
			// PIPE/EXEC, which classic rejects; intersection is authoritative.
			{name: "fs-noatime", desc: "set FS_NOATIME_FL on the file", aliases: []string{"ext2-noatime", "ext3-noatime"}},
			{name: "f-setpipe-sz", desc: "set Linux pipe capacity", aliases: []string{"pipesz"}, addressTypes: fdOptionAddressTypes(), validate: validateInteger(1)},
			{name: "perm", desc: "chmod after open or on an exposed fd (classic TYPE_MODET)", aliases: []string{"mode"}, validate: validateOctal(0o7777)},
			{name: "perm-early", desc: "chmod existing name before open, or UNIX socket after bind", validate: validateOctal(0o7777)},
			{name: "ftruncate", desc: "ftruncate(2) an opened regular file to this length", aliases: []string{"truncate", "ftruncate32", "ftruncate64"}, validate: validateInteger(0)},
			{name: "setlk", desc: "nonblocking whole-file write lock", aliases: []string{"f-setlk-wr"}},
			{name: "setlkw", desc: "blocking whole-file write lock", aliases: []string{"f-setlkw-wr"}},
			{name: "setlk-rd", desc: "nonblocking whole-file read lock", aliases: []string{"f-setlk-rd"}},
			{name: "setlkw-rd", desc: "blocking whole-file read lock", aliases: []string{"f-setlkw-rd"}},
			{name: "umask", desc: "umask during open or EXEC start", validate: validateOctal(0o777)},
			{name: "user", desc: "file owner", aliases: []string{"uid", "owner"}, validate: validateRequiredString},
			{name: "group", desc: "file group", aliases: []string{"gid"}, validate: validateRequiredString},
			{name: "user-early", desc: "chown existing name before open, or UNIX socket after bind", aliases: []string{"uid-e"}, validate: validateRequiredString},
			{name: "group-early", desc: "chgrp existing name before open, or UNIX socket after bind", aliases: []string{"gid-e"}, validate: validateRequiredString},
			{name: "unlink-early", desc: "unlink before bind/open"},
			{name: "unlink", desc: "unlink before open", aliases: []string{"delete", "remove"}},
			{name: "unlink-close", desc: "unlink on close"},
			{name: "unlink-late", desc: "unlink immediately after open"},
			{name: "unix-bind-tempname", desc: "bind a temporary UNIX name", aliases: []string{"bind-tempname"}},
			{name: "socktype", dynamicDesc: xio.UnixSocktypeHelp, aliases: []string{"so-type", "type"}, validate: validateInteger(-1)},
		}},
	}
}
