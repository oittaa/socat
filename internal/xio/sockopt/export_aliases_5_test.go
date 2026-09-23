//go:build linux || darwin

package sockopt

// Test aliases for unexported socket-option names.
var ApplyPreparedMulticast = applyPreparedMulticast
var HandleIPv4Cmsg = handleIPv4Cmsg
var ParseCmsgTimeval = parseCmsgTimeval
var ParseInet4Pktinfo = parseInet4Pktinfo
var ParseInet6Pktinfo = parseInet6Pktinfo
var ResolveJoinInterface = resolveJoinInterface

const SoKeepalive = soKeepalive
