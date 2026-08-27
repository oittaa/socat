//go:build freebsd

package netopen

// FreeBSD <netinet/udplite.h> uses different option numbers than Linux.
const (
	udpliteSendCscov = 2
	udpliteRecvCscov = 4
)
