package xio

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
)

// ResolvePreparedPaths implements per-address chdir= without changing the
// process-wide working directory. Filesystem parameters and path-valued
// settings are made absolute; EXEC/SYSTEM/SHELL receive the directory through
// exec.Cmd.Dir.
func ResolvePreparedPaths(config addrconfig.Address) (addrconfig.Address, error) {
	if !config.Process.Chdir.Set {
		return config, nil
	}
	dir := strings.TrimSpace(config.Process.Chdir.Value)
	if dir == "" {
		return addrconfig.Address{}, fmt.Errorf("%s: option %q requires a directory", config.Type, "chdir")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return addrconfig.Address{}, fmt.Errorf("%s: chdir %q: %w", config.Type, dir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return addrconfig.Address{}, fmt.Errorf("%s: chdir %q: %w", config.Type, dir, err)
	}
	if !info.IsDir() {
		return addrconfig.Address{}, fmt.Errorf("%s: chdir %q: not a directory", config.Type, dir)
	}

	config.Params = append([]string(nil), config.Params...)
	config.Process.Chdir.Value = abs
	if filesystemAddressParam(config) && config.File.Path != "" {
		config.File.Path = resolveRelativePath(abs, config.File.Path)
	}
	if unixAddressType(config) && config.Network.SocketPath != "" {
		config.Network.SocketPath = resolveRelativePath(abs, config.Network.SocketPath)
	}
	if filesystemAddressParam(config) && len(config.Params) > 0 {
		config.Params[0] = resolveRelativePath(abs, config.Params[0])
	}
	resolveOptionalPath(&config.Terminal.Link, abs)
	resolveOptionalPath(&config.TLS.Certificate, abs)
	resolveOptionalPath(&config.TLS.Key, abs)
	resolveOptionalPath(&config.TLS.CAFile, abs)
	resolveOptionalPath(&config.TLS.CAPath, abs)
	resolveOptionalPath(&config.Proxy.AuthorizationFile, abs)
	resolveOptionalPath(&config.Network.UnixBindTempname, abs)
	resolveOptionalPath(&config.Network.HostsAllow, abs)
	resolveOptionalPath(&config.Network.HostsDeny, abs)
	resolveOptionalPath(&config.Network.TCPWrapEtc, abs)
	if config.Network.TUNDevice != "" {
		config.Network.TUNDevice = resolveRelativePath(abs, config.Network.TUNDevice)
	}
	if config.File.LockSet {
		config.File.LockPath = resolveRelativePath(abs, config.File.LockPath)
	}
	if filesystemBindAddress(config) && config.Network.BindSet {
		config.Network.Bind = resolveFilesystemBind(abs, config.Network.Bind)
	}
	return config, nil
}

func resolveOptionalPath(value *addrconfig.OptionalString, dir string) {
	if value.Set {
		value.Value = resolveRelativePath(dir, value.Value)
	}
}

func resolveFilesystemBind(dir string, target addrconfig.HostTarget) addrconfig.HostTarget {
	name := target.Original()
	if name == "" || IsAbstract(name) {
		return target
	}
	return addrconfig.HostTarget{Name: resolveRelativePath(dir, name)}
}

func resolveRelativePath(dir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

func filesystemAddressParam(config addrconfig.Address) bool {
	switch config.Facts.Kind {
	case addrconfig.AddressKindFile, addrconfig.AddressKindCREATE, addrconfig.AddressKindPIPE, addrconfig.AddressKindGOPEN, addrconfig.AddressKindUNIX:
		return true
	default:
		return false
	}
}

func unixAddressType(config addrconfig.Address) bool {
	return config.Facts.Kind == addrconfig.AddressKindUNIX
}

func filesystemBindAddress(config addrconfig.Address) bool {
	switch config.Facts.Kind {
	case addrconfig.AddressKindUNIX, addrconfig.AddressKindGOPEN:
		return true
	default:
		return false
	}
}
