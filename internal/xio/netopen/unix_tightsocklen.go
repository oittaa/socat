package netopen

import "github.com/oittaa/socat/internal/parse"

// unixTightSocklen is classic unix-tightsocklen / tightsocklen (xio-unix.c
// PH_PREBIND TYPE_BOOL, default UNIX_TIGHTSOCKLEN). tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same.
//
// Linux and Darwin default true. Omitted and =1 keep Go's net.Listen/Dial
// bind length. =0 uses sizeof(sockaddr_un).
func unixTightSocklen(s parse.Spec) bool {
	if !s.HasOption("unix-tightsocklen") {
		return true
	}
	return s.BoolOption("unix-tightsocklen")
}

// classicUnixSockaddrLen is xiosetunix's returned socklen_t.
// sizeofUn is sizeof(struct sockaddr_un); sunPath is sizeof(sun_path).
// abstract pathlen is strlen of the name without the leading NUL.
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
