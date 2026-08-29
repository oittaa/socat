package netopen

import (
	"runtime"

	"github.com/oittaa/socat/internal/parse"
)

// unixTightSocklen is unix-tightsocklen / tightsocklen. Bare flag → 1;
// unix-tightsocklen=0 still applies. Default is tight on Linux and macOS;
// Windows listen/dial reject the option, and bindUnixPath rejects =0.
// Tight pathname length excludes the terminator Go's net routines include.
func unixTightSocklen(s parse.Spec) bool {
	if !s.HasOption("unix-tightsocklen") {
		return unixTightSocklenDefault(runtime.GOOS)
	}
	return s.BoolOption("unix-tightsocklen")
}

func unixTightSocklenDefault(goos string) bool {
	switch goos {
	case "freebsd", "openbsd":
		return false
	default:
		return true
	}
}

// classicUnixSockaddrLen is the bind/connect socklen for a pathname or
// abstract name. sizeofUn is sizeof(struct sockaddr_un); sunPath is
// sizeof(sun_path). abstract pathlen is strlen of the name without the
// leading NUL.
func classicUnixSockaddrLen(pathlen, sunPath, sizeofUn int, abstract, tight bool) int {
	if !tight {
		return sizeofUn
	}
	off := sizeofUn - sunPath
	if abstract {
		n := pathlen + 1
		if n > sunPath {
			n = sunPath
		}
		return off + n
	}
	if pathlen > sunPath {
		pathlen = sunPath
	}
	return off + pathlen
}
