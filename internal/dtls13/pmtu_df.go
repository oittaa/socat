package dtls13

import "syscall"

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

func enableUnfragmentedSends(conn syscallConn) (bool, error) {
	if conn == nil {
		return false, nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return false, err
	}
	return setUnfragmentedDF(raw)
}

func (p *packetTransport) configureUnfragmentedProbes(optIn bool) {
	p.unfragmented = false
	if !optIn || !p.direct || p.udp == nil {
		return
	}
	ok, err := enableUnfragmentedSends(p.udp)
	if err != nil || !ok {
		return
	}
	p.unfragmented = true
}
