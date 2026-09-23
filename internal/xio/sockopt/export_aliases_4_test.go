//go:build linux && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package sockopt

// Test aliases for unexported socket-option names.
type GroupSourceReq = groupSourceReq

const GroupSourceReqSize = groupSourceReqSize
