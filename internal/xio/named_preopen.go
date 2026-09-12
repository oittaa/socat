package xio

import (
	"os"

	"github.com/oittaa/socat/internal/addrconfig"
)

// ApplyConfiguredNamedAfterBind applies typed named options to a filesystem
// UNIX socket after bind. UNIX-CONNECT and UNIX-SENDTO apply those options to
// the socket descriptor instead. Abstract names have no filesystem entry.
//
// perm-early is a no-op before bind because the directory entry does not
// exist yet; after bind it chmods the new socket and wins over perm= on
// listen/recv names. unlink= at this phase would remove the just-bound name.
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
func FDSkipNamedUnixSocket(s addrconfig.Address) FDSkip {
	if namedFilesystemUnixSocket(s) {
		return FDSkipOwner
	}
	return FDSkip{}
}

// namedFilesystemUnixSocket is true after bind of a filesystem UNIX listen
// or recv name. Abstract names have no directory entry.
func namedFilesystemUnixSocket(config addrconfig.Address) bool {
	if config.Facts.Kind != addrconfig.AddressKindUNIX {
		return false
	}
	switch config.Facts.Role {
	case addrconfig.AddressRoleListen, addrconfig.AddressRoleReceive, addrconfig.AddressRoleReceiveFrom:
	default:
		return false
	}
	if len(config.Params) > 0 && IsAbstract(config.Params[0]) {
		return false
	}
	return true
}
