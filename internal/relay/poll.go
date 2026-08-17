package relay

type pollfd struct {
	Fd      int32
	Events  int16
	Revents int16
}
