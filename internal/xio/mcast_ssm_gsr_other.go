//go:build linux || freebsd

package xio

// groupSourceReq is C struct group_source_req on Linux/FreeBSD 64-bit:
// uint32 gsr_interface, 4 bytes padding, two sockaddr_storage (264 bytes).
// golang.org/x/net ipv6 sizeofGroupSourceReq = 0x108.
type groupSourceReq struct {
	Interface uint32
	_         [4]byte
	Group     [128]byte
	Source    [128]byte
}
