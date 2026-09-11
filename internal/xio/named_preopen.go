package xio

import (
	"context"
	"os"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

// ApplyNamedPreopen applies perm-early / user-early / group-early and unlink
// to an existing filesystem path, in command-line order, before open.
// unlink=0 does not delete.
//
// Callers must invoke this only when the name exists. UNIX bind paths call
// ApplyNamedAfterBind once the directory entry exists.
func ApplyNamedPreopen(path string, s parse.Spec) error {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return err
	}
	return ApplyConfiguredNamedPreopen(path, config.File)
}

// ApplyNamedAfterBind applies named options to a filesystem UNIX socket
// after bind. UNIX-CONNECT and UNIX-SENDTO apply those options to the
// socket descriptor instead. Abstract names have no filesystem entry.
//
// perm-early is a no-op before bind because the directory entry does not
// exist yet; after bind it chmods the new socket and wins over perm= on
// listen/recv names. unlink= at this phase would remove the just-bound name.
func ApplyNamedAfterBind(path string, s parse.Spec, f *os.File) error {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return err
	}
	return ApplyConfiguredNamedAfterBind(path, config, f)
}

// ApplyNamedAttrs applies perm/user/group to a filesystem name in
// command-line order. Regular files and FIFOs pass perm= to open(2)/mkfifo
// so umask still applies; do not use ApplyNamedAttrs as create-mode for those.
func ApplyNamedAttrs(path string, s parse.Spec, f *os.File) error {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return err
	}
	return ApplyConfiguredNamedAttrs(path, f, config.File)
}

// ApplyConfiguredNamedAfterBind applies typed named options to a filesystem
// UNIX socket after bind.
func ApplyConfiguredNamedAfterBind(path string, config addrconfig.Address, f *os.File) error {
	if path == "" || IsAbstract(path) {
		return nil
	}
	if namedFilesystemUnixSocket(config) {
		if err := ApplyConfiguredNamedAttrs(path, f, config.File); err != nil {
			return err
		}
	}
	return ApplyConfiguredNamedPreopen(path, config.File)
}

// FDSkipNamedUnixSocket skips perm/user/group on a UNIX datagram fd when
// those options were applied to the filesystem name after bind.
func FDSkipNamedUnixSocket(s parse.Spec) FDSkip {
	config, err := OpeningConfig(context.Background(), s)
	if err != nil {
		return FDSkip{}
	}
	return FDSkipNamedUnixSocketConfig(config)
}

// FDSkipNamedUnixSocketConfig skips perm/user/group when those options were
// applied to the filesystem name after bind.
func FDSkipNamedUnixSocketConfig(config addrconfig.Address) FDSkip {
	if namedFilesystemUnixSocket(config) {
		return FDSkipOwner
	}
	return FDSkip{}
}

// namedFilesystemUnixSocket is true after bind of a filesystem UNIX listen
// or recv name. Abstract names have no directory entry.
func namedFilesystemUnixSocket(config addrconfig.Address) bool {
	switch strings.ToUpper(config.Type) {
	case "UNIX-LISTEN", "UNIX-L", "UNIX-RECV", "UNIX-RECVFROM":
	default:
		return false
	}
	if len(config.Params) > 0 && IsAbstract(config.Params[0]) {
		return false
	}
	return true
}
