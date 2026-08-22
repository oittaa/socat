package parse

import (
	"strings"
)

func looksLikePath(s string) bool {
	// Classic: if '/' before first ':' or ',', assume GOPEN.
	// Native Windows: C:\..., C:/..., or UNC \\server\share.
	if hasWindowsVolume(s) {
		return true
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '/':
			return true
		case '\\':
			return nativeWindowsPathSeparators
		case ':', ',':
			return false
		}
	}
	return false
}

// looksLikeWindowsPath reports a native Windows path: drive + slash or UNC.
func looksLikeWindowsPath(s string) bool {
	if hasWindowsVolume(s) {
		return true
	}
	// A single leading backslash and separator-containing relative paths are
	// native Windows forms. Do not reinterpret them on Unix, where backslash
	// remains the classic socat escape character.
	return nativeWindowsPathSeparators && strings.Contains(s, `\`)
}

func hasWindowsVolume(s string) bool {
	if len(s) >= 2 {
		c := s[0]
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) && s[1] == ':' {
			return true
		}
	}
	if len(s) >= 2 && s[0] == '\\' && s[1] == '\\' {
		return true
	}
	return false
}

// isWindowsDriveColon reports the colon in X:\ or X:/ at the start of s[start:].
func isWindowsDriveColon(s string, start, i int) bool {
	if i != start+1 || i+1 >= len(s) {
		return false
	}
	c := s[start]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}
	n := s[i+1]
	return n == '\\' || n == '/'
}

// pathParamType reports address types whose positional argument is one path.
func pathParamType(typeName string) bool {
	n := strings.ToUpper(typeName)
	switch n {
	case "OPEN", "FILE", "CREATE", "CREAT", "GOPEN", "PIPE", "FIFO", "ECHO":
		return true
	}
	// Classic UNIX addresses use ':' as the positional-parameter separator;
	// test.sh relies on UNIX-LISTEN::::: failing immediately. Preserve the
	// whole value only on Windows, where a native drive path must stay intact.
	return nativeWindowsPathSeparators && strings.HasPrefix(n, "UNIX")
}

// pathOption reports option values that are interpreted as filesystem paths.
func pathOption(name string) bool {
	switch normalizeOptionName(name) {
	case "cert", "key", "cafile", "capath", "chdir", "link",
		"hosts-allow", "hosts-deny", "proxy-authorization-file",
		"unix-bind-tempname":
		return true
	default:
		return false
	}
}
