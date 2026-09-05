package dtls13

import (
	"errors"
	"fmt"
)

type alertError byte

const (
	errUnexpectedMessage     = alertError(10)
	errHandshakeFailure      = alertError(40)
	errBadCertificate        = alertError(42)
	errCertificateExpired    = alertError(45)
	errIllegalParameter      = alertError(47)
	errUnknownCA             = alertError(48)
	errDecode                = alertError(50)
	errDecrypt               = alertError(51)
	errProtocolVersion       = alertError(70)
	errInternal              = alertError(80)
	errMissingExtension      = alertError(109)
	errUnsupportedExtension  = alertError(110)
	errCertificateRequired   = alertError(116)
	errNoApplicationProtocol = alertError(120)
)

func (a alertError) Error() string {
	name := ""
	switch a {
	case errUnexpectedMessage:
		name = "unexpected message"
	case errHandshakeFailure:
		name = "handshake failure"
	case errBadCertificate:
		name = "bad certificate"
	case errCertificateExpired:
		name = "certificate expired"
	case errIllegalParameter:
		name = "illegal parameter"
	case errUnknownCA:
		name = "unknown certificate authority"
	case errDecode:
		name = "malformed handshake message"
	case errDecrypt:
		name = "handshake authentication failed"
	case errProtocolVersion:
		name = "unsupported protocol version"
	case errInternal:
		name = "internal error"
	case errMissingExtension:
		name = "missing extension"
	case errUnsupportedExtension:
		name = "unsupported extension"
	case errCertificateRequired:
		name = "client certificate required"
	case errNoApplicationProtocol:
		name = "no shared application protocol"
	default:
		return fmt.Sprintf("dtls: alert %d", byte(a))
	}
	return "dtls: " + name
}

func errorAlert(err error) []byte {
	var alert alertError
	if errors.As(err, &alert) {
		return []byte{2, byte(alert)}
	}
	switch {
	case errors.Is(err, errSignature):
		return []byte{2, byte(errDecrypt)}
	case errors.Is(err, errCertificate):
		return []byte{2, byte(errBadCertificate)}
	case errors.Is(err, errRecordOverflow):
		return []byte{2, 22}
	default:
		return []byte{2, byte(errInternal)}
	}
}
