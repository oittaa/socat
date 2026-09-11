package xio

import "errors"

// Named SOL_SOCKET, TCP, and Linux SCTP integer socket options.
// Bare flag → 1. Kernel rejection fails the call. Linux SO_SNDLOWAT is
// recognized but rejected (kernel ENOPROTOOPT). nopush/noopt work on Darwin;
// Linux and Windows reject. so-bsdcompat, tcp-info, tcp-md5sig, and
// sctp-maxseg-late are not implemented. sctp-nodelay/sctp-maxseg use SOL_SCTP.
var errNamedOptUnsupported = errors.New("not supported on this platform")
