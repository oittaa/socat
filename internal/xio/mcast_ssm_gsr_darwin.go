//go:build darwin

package xio

// groupSourceReq is Darwin struct group_source_req: uint32 then two
// sockaddr_storage with no padding (260 bytes). x/net ipv6
// sizeofGroupSourceReq = 0x104; setSourceGroup writes at offsets 4 and 132.
type groupSourceReq struct {
	Interface uint32
	Group     [128]byte
	Source    [128]byte
}

const groupSourceReqSize = 260
