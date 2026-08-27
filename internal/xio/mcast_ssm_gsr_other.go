//go:build (linux && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)) || (freebsd && (amd64 || arm || arm64 || riscv64))

package xio

// groupSourceReq is C struct group_source_req on platforms where
// sockaddr_storage has 8-byte alignment: uint32 gsr_interface, 4 bytes
// padding, then two sockaddr_storage values (264 bytes). These platform and
// architecture splits match golang.org/x/net's generated sizeofGroupSourceReq.
type groupSourceReq struct {
	Interface uint32
	_         [4]byte
	Group     [128]byte
	Source    [128]byte
}

const groupSourceReqSize = 264
