//go:build linux

package sockopt

// Test aliases for unexported socket-option names.
const SctpMaxseg = sctpMaxseg
const SctpNodelay = sctpNodelay

var SetIPv4MembershipFD = setIPv4MembershipFD

const SolSCTP = solSCTP
