//go:build linux && (386 || arm || mips || mipsle || ppc)

package sockopt

// Test aliases for unexported socket-option names.
type GroupSourceReq = groupSourceReq

const GroupSourceReqSize = groupSourceReqSize
