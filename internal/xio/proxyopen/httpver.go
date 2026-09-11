package proxyopen

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

type httpMajor int

const (
	httpVer1 httpMajor = 1
	httpVer2 httpMajor = 2
	httpVer3 httpMajor = 3
)

func rejectProxyPlaintextPolicy(s parse.Spec) error {
	major, err := parseHTTPVersion(s)
	if err != nil {
		return err
	}
	h2c := s.BoolOption("h2c")
	if h2c && major != httpVer2 {
		return fmt.Errorf("h2c requires http-version=2")
	}
	if s.BoolOption("ignorecr") && major != httpVer1 {
		return fmt.Errorf("ignorecr applies only to HTTP/1 CONNECT responses")
	}
	if major == httpVer1 || (major == httpVer2 && h2c) {
		return tlsopen.RejectPROXYTLSOnPlaintext(s)
	}
	return nil
}

func parseHTTPVersion(s parse.Spec) (httpMajor, error) {
	v := s.OptionValue("http-version", "1.0")
	if v == "" {
		v = "1.0"
	}
	switch strings.TrimSpace(v) {
	case "1", "1.0", "1.1":
		return httpVer1, nil
	case "2", "2.0":
		return httpVer2, nil
	case "3", "3.0":
		return httpVer3, nil
	default:
		return 0, fmt.Errorf("http-version=%s not supported (use 1.0, 1.1, 2, or 3)", v)
	}
}

func proxyHTTPVersion(p addrconfig.Proxy) (httpMajor, string) {
	switch p.HTTPVersion {
	case addrconfig.HTTPVersion11:
		return httpVer1, "1.1"
	case addrconfig.HTTPVersion2:
		return httpVer2, "2"
	case addrconfig.HTTPVersion3:
		return httpVer3, "3"
	default:
		return httpVer1, "1.0"
	}
}

func proxyPortText(p addrconfig.Proxy) string {
	if p.Port.Set && p.Port.Value != "" {
		return p.Port.Value
	}
	return "8080"
}

func proxyResolveTarget(p addrconfig.Proxy) bool {
	if p.Resolve.Set {
		return p.Resolve.Value
	}
	return true
}

func proxyALPN(settings addrconfig.TLS, def string) string {
	if settings.ALPN.Set && settings.ALPN.Value != "" {
		return settings.ALPN.Value
	}
	return def
}
