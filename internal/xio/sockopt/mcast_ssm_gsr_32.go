//go:build linux && (386 || arm || mips || mipsle)

package sockopt

// groupSourceReq is C struct group_source_req on 32-bit linux ports, where
// the two sockaddr_storage values immediately follow the uint32 interface
// index. The layout matches golang.org/x/net's sizeofGroupSourceReq.
type groupSourceReq struct {
	Interface uint32
	Group     [128]byte
	Source    [128]byte
}

const groupSourceReqSize = 260
