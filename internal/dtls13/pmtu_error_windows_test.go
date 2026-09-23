//go:build windows

package dtls13

func messageTooLongError() error {
	return wsaEMSGSIZE
}
