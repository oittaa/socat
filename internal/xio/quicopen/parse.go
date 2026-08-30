// Package quicopen implements raw QUIC byte relay (RFC 9000) connect and listen.
// One bidirectional stream via github.com/quic-go/quic-go — not HTTP/3.
package quicopen

import (
	"crypto/tls"
	"fmt"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

const defaultALPN = "socat"

func quicTarget(s parse.Spec, listen bool) (host, port string, err error) {
	if listen {
		if len(s.Params) < 1 || s.Params[0] == "" {
			return "", "", fmt.Errorf("%s requires port", s.Type)
		}
		return "", s.Params[0], nil
	}
	return xio.HostPortParams(s)
}

func alpnProto(s parse.Spec) string {
	v := s.OptionValue("alpn", "")
	if v == "" {
		return defaultALPN
	}
	return v
}

func withALPN(cfg *tls.Config, s parse.Spec) (*tls.Config, error) {
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		return nil, fmt.Errorf("openssl-max-proto-version: QUIC requires TLS 1.3 or later")
	}
	cfg.NextProtos = []string{alpnProto(s)}
	// RFC 9001 requires clients not to offer versions older than TLS 1.3.
	// Preserve a higher minimum if a future TLS implementation supports one.
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	return cfg, nil
}
