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
	if filesystemAddressParam(config.Type) && len(config.Params) > 0 {
		config.Params[0] = resolveRelativePath(abs, config.Params[0])
	}
	resolveOptionalPath(&config.Terminal.Link, abs)
	resolveOptionalPath(&config.TLS.Certificate, abs)
	resolveOptionalPath(&config.TLS.Key, abs)
	resolveOptionalPath(&config.TLS.CAFile, abs)
	resolveOptionalPath(&config.TLS.CAPath, abs)
	resolveOptionalPath(&config.Proxy.AuthorizationFile, abs)
	resolveOptionalPath(&config.Network.UnixBindTempname, abs)
	resolveOptionalPath(&config.Network.Peer.HostsAllow, abs)
	resolveOptionalPath(&config.Network.Peer.HostsDeny, abs)
	resolveOptionalPath(&config.Network.Peer.TCPWrapEtc, abs)
	if config.Network.TUN.Device != "" {
		config.Network.TUN.Device = resolveRelativePath(abs, config.Network.TUN.Device)
	}
	if config.File.Lock.Set {
		config.File.Lock.Path = resolveRelativePath(abs, config.File.Lock.Path)
	}
	if unixAddressType(config.Type) {
		resolveOptionalPath(&config.Common.ConnectBind, abs)
		if config.Network.BindSet {
			config.Network.Bind = resolveHostPath(abs, config.Network.Bind)
		}
	}
	return config, nil
}

func resolveOptionalPath(value *addrconfig.OptionalString, dir string) {
	if value.Set {
		value.Value = resolveRelativePath(dir, value.Value)
	}
}

func resolveHostPath(dir string, target addrconfig.HostTarget) addrconfig.HostTarget {
	if target.IsLiteral() {
		return target
	}
	target.Name = resolveRelativePath(dir, target.Name)
	return target
}

func resolveRelativePath(dir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

func filesystemAddressParam(typ string) bool {
	typ = strings.ToUpper(typ)
	switch typ {
	case "OPEN", "FILE", "CREATE", "CREAT", "GOPEN", "PIPE", "FIFO", "ECHO":
		return true
	}
	return unixAddressType(typ)
}

func unixAddressType(typ string) bool {
	return strings.HasPrefix(strings.ToUpper(typ), "UNIX")
}
