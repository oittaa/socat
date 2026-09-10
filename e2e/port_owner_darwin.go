//go:build e2e && darwin && cgo

// Darwin listen-owner check. Cgo cannot live in *_test.go, so this stays a
// non-test file in package e2e and the e2e_test suite calls ProcessListens.

package e2e

/*
#include <libproc.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int socat_e2e_pid_listens(int pid, int is_udp, int port) {
	int sz = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
	if (sz <= 0) {
		return 0;
	}
	struct proc_fdinfo *fds = malloc((size_t)sz);
	if (fds == NULL) {
		return -1;
	}
	int n = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sz);
	if (n <= 0) {
		free(fds);
		return 0;
	}
	int count = n / (int)sizeof(struct proc_fdinfo);
	int found = 0;
	for (int i = 0; i < count; i++) {
		if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) {
			continue;
		}
		struct socket_fdinfo info;
		memset(&info, 0, sizeof(info));
		int got = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &info, (int)sizeof(info));
		if (got < (int)sizeof(info)) {
			continue;
		}
		int lport = 0;
		if (is_udp) {
			if (info.psi.soi_type != SOCK_DGRAM) {
				continue;
			}
			lport = (int)ntohs((uint16_t)info.psi.soi_proto.pri_in.insi_lport);
		} else {
			if (info.psi.soi_kind != SOCKINFO_TCP) {
				continue;
			}
			if (info.psi.soi_proto.pri_tcp.tcpsi_state != TSI_S_LISTEN) {
				continue;
			}
			lport = (int)ntohs((uint16_t)info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
		}
		if (lport == port) {
			found = 1;
			break;
		}
	}
	free(fds);
	return found;
}
*/
import "C"

import (
	"net"
	"strconv"
	"strings"
)

// ProcessListens reports whether pid owns a listen/bound socket on addr.
func ProcessListens(pid int, network, addr string) (bool, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false, err
	}
	isUDP := 0
	if strings.HasPrefix(network, "udp") {
		isUDP = 1
	}
	n, errno := C.socat_e2e_pid_listens(C.int(pid), C.int(isUDP), C.int(port))
	return listenOwnerFromC(int(n), errno)
}
