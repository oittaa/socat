package xio

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// ResolveChdirPaths implements per-address chdir= without changing the
// process-wide working directory. Filesystem parameters are made absolute and
// EXEC/SYSTEM/SHELL receive the resolved directory through exec.Cmd.Dir.
func ResolveChdirPaths(s parse.Spec) (parse.Spec, error) {
	o, ok := s.OptionNamed("chdir")
	if !ok {
		return s, nil
	}
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return parse.Spec{}, fmt.Errorf("%s: option %q requires a directory", s.Type, o.Name)
	}
	dir, err := filepath.Abs(o.Value)
	if err != nil {
		return parse.Spec{}, fmt.Errorf("%s: chdir %q: %w", s.Type, o.Value, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return parse.Spec{}, fmt.Errorf("%s: chdir %q: %w", s.Type, o.Value, err)
	}
	if !info.IsDir() {
		return parse.Spec{}, fmt.Errorf("%s: chdir %q: not a directory", s.Type, o.Value)
	}

	s.Params = append([]string(nil), s.Params...)
	s.Options = append([]parse.Option(nil), s.Options...)
	if filesystemAddressParam(s.Type) && len(s.Params) > 0 {
		s.Params[0] = resolveRelativePath(dir, s.Params[0])
	}

	unixPaths := strings.HasPrefix(strings.ToUpper(s.Type), "UNIX")
	for i := range s.Options {
		name := strings.ToLower(s.Options[i].Name)
		if name == "chdir" {
			s.Options[i].Value = dir
			continue
		}
		if !s.Options[i].Has || s.Options[i].Value == "" {
			continue
		}
		if filesystemOption(name) || unixPaths && name == "bind" {
			s.Options[i].Value = resolveRelativePath(dir, s.Options[i].Value)
		}
	}
	return s, nil
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
	return strings.HasPrefix(typ, "UNIX")
}

func filesystemOption(name string) bool {
	switch parse.CanonicalOptionName(name) {
	case "cert", "key", "cafile", "ca", "capath", "link", "symbolic-link",
		"hosts-allow", "allow-table", "tcpwrap-hosts-allow-table",
		"hosts-deny", "deny-table", "tcpwrap-hosts-deny-table",
		"tcpwrap-etc", "tcpwrap-dir", "proxy-authorization-file",
		"unix-bind-tempname", "bind-tempname", "tun-device",
		"lockfile", "waitlock":
		return true
	default:
		return false
	}
}
