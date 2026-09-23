package sockopt

// AncillaryBufferSize is the control-message buffer for one recvmsg.
const AncillaryBufferSize = 1024

// Session receives ancillary logs and per-session output variables.
type Session interface {
	Infof(string, ...any)
	Noticef(string, ...any)
	SetSessionVar(string, string)
}
