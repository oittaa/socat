//go:build linux && (386 || arm || mips || mipsle || ppc)

package xio

// groupSourceReq is C struct group_source_req on platforms where the two
// sockaddr_storage values immediately follow the uint32 interface index.
// These platform and architecture splits match golang.org/x/net's generated
// sizeofGroupSourceReq.
type groupSourceReq struct {
	Interface uint32
	Group     [128]byte
	Source    [128]byte
}

const groupSourceReqSize = 260
