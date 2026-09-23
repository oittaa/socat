package xio

import (
	"syscall"

	"github.com/oittaa/socat/internal/xio/sockopt"
)

func init() {
	sockopt.ApplyConnFDLifecycle = ApplyFDLifecycleToConn
	sockopt.DrainRecvErr = func(err error, enabled bool, c syscall.Conn, g sockopt.Session) {
		var gl *Global
		if g != nil {
			gl, _ = g.(*Global)
		}
		DrainRecvErrOnError(err, enabled, c, gl)
	}
	sockopt.AddressGroup = func(typ string) (string, bool) {
		reg, ok := AddressRegistrationForType(typ)
		if !ok {
			return "", false
		}
		return reg.Group, true
	}
}
