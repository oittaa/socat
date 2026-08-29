package classiccatalog

// Named SOL_SOCKET options not yet implemented. Probe read-only sockopts on
// each OS before advertising; do not advertise a no-op.
//
// The SOL_SOCKET / ioctl audit (PR D) implemented fiosetown / siocspgrp and
// classified get-only, BPF TYPE_INT, and obsolete SO_SECURITY_* names as
// unsupportedSocketIoctl. so-bsdcompat is unsupportedNoopSockopts.
var expectedMissingSocket = map[string]Gap{}
