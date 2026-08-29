package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// applyOwnerIoctlOption is classic xio-socket.c opt_fiosetown / opt_siocspgrp
// (https://repo.or.cz/socat.git tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree):
// GROUP_SOCKET, PH_PASTSOCKET, TYPE_INT, OFUNC_IOCTL, FIOSETOWN / SIOCSPGRP,
// nicknames NULL.
//
// Official man COMMENTs fiosetown=<pid_t> / siocspgrp=<pid_t>. C
// parseopts_table TYPE_INT without '=' stores 1 (pid 1). This port follows C,
// not the COMMENTed required-value wording (same man/C split as so-passcred).
//
// applyopt_ioctl calls Ioctl(fd, major, (void *)&opt->value): pointer to a
// C int, matching ioctl-intp / unix.IoctlSetPointerInt. Assigned values are
// overflow-safe C int (parseClassicCInt); negatives are process groups.
func applyOwnerIoctlOption(fd int, o parse.Option) (bool, error) {
	if !isOwnerIoctlOption(o.Name) {
		return false, nil
	}
	n, err := parseOwnerIoctlValue(o)
	if err != nil {
		return true, err
	}
	if err := applyOwnerIoctlPlatform(fd, o.Name, n); err != nil {
		return true, fmt.Errorf("%s: %w", o.Name, err)
	}
	return true, nil
}

func isOwnerIoctlOption(name string) bool {
	switch name {
	case "fiosetown", "siocspgrp":
		return true
	default:
		return false
	}
}

func parseOwnerIoctlValue(o parse.Option) (int, error) {
	if !o.Has {
		return 1, nil
	}
	n, err := parseClassicCInt(o.Value)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid value %q", o.Name, o.Value)
	}
	return n, nil
}
