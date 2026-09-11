package addrconfig

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// TLS holds static TLS settings. Certificate and CA paths remain live inputs.
type TLS struct {
	Certificate  OptionalString
	Key          OptionalString
	CAFile       OptionalString
	CAPath       OptionalString
	Verify       OptionalBool
	CommonName   OptionalString
	SNIHost      OptionalString
	NoSNI        OptionalBool
	CipherSuites []uint16
	MinVersion   uint16
	MaxVersion   uint16
	ALPN         OptionalString
}

// DTLS holds the DTLS-specific static policy.
type DTLS struct {
	MTU                OptionalInt
	Migration          OptionalBool
	UnfragmentedProbes OptionalBool
	MinVersion         OptionalInt
	MaxVersion         OptionalInt
}

// HTTPVersion selects a CONNECT transport.
type HTTPVersion uint8

const (
	HTTPVersion10 HTTPVersion = iota + 1
	HTTPVersion11
	HTTPVersion2
	HTTPVersion3
)

// Proxy holds static HTTP CONNECT and SOCKS settings.
type Proxy struct {
	Port              OptionalString
	HTTPVersion       HTTPVersion
	H2C               OptionalBool
	IgnoreCR          OptionalBool
	Resolve           OptionalBool
	Authorization     OptionalString
	AuthorizationFile OptionalString
	SOCKSPort         OptionalString
	SOCKSUser         OptionalString
	SOCKSPassword     OptionalString
}

// WebSocket holds WebSocket-only textual payloads. Protocol deliberately stays
// case-sensitive and distinct from a socket protocol number.
type WebSocket struct {
	Path     OptionalString
	Origin   OptionalString
	Protocol OptionalString
}

func decodeProtocolOption(a *Address, o parse.Option) (bool, error) {
	name := optionIdentity(o)
	switch name {
	case "cert":
		return true, decodeProtocolString(&a.TLS.Certificate, o)
	case "key":
		return true, decodeProtocolString(&a.TLS.Key, o)
	case "cafile":
		return true, decodeProtocolString(&a.TLS.CAFile, o)
	case "capath":
		return true, decodeProtocolString(&a.TLS.CAPath, o)
	case "verify":
		value, err := optionalBool(o)
		a.TLS.Verify = value
		return true, err
	case "commonname":
		if !o.Has {
			return true, nil
		}
		a.TLS.CommonName = OptionalString{Set: true, Value: o.Value}
		return true, nil
	case "snihost":
		if !o.Has {
			return true, fmt.Errorf("option %q requires a value", o.OriginalSpelling())
		}
		a.TLS.SNIHost = OptionalString{Set: true, Value: o.Value}
		return true, nil
	case "nosni":
		value, err := optionalBool(o)
		a.TLS.NoSNI = value
		return true, err
	case "ciphers":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		suites, err := decodeCipherSuites(value)
		if err != nil {
			return true, err
		}
		a.TLS.CipherSuites = suites
		return true, nil
	case "openssl-min-proto-version":
		return true, decodeProtocolVersion(a, o, true)
	case "openssl-max-proto-version":
		return true, decodeProtocolVersion(a, o, false)
	case "alpn":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		if len(value) > 255 {
			return true, fmt.Errorf("alpn: protocol must contain 1 to 255 bytes")
		}
		a.TLS.ALPN = OptionalString{Set: true, Value: value}
		return true, nil
	case "dtls-mtu":
		value, err := requiredInt(o, 256)
		if err != nil || value > 65507 {
			return true, fmt.Errorf("dtls-mtu: value must be between 256 and 65507")
		}
		a.DTLS.MTU = OptionalInt{Set: true, Value: value}
		return true, nil
	case "dtls-migration":
		value, err := optionalBool(o)
		a.DTLS.Migration = value
		return true, err
	case "dtls-unfragmented-probes":
		value, err := optionalBool(o)
		a.DTLS.UnfragmentedProbes = value
		return true, err
	case "proxyport":
		return true, decodeProtocolString(&a.Proxy.Port, o)
	case "http-version":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		version, err := decodeHTTPVersion(value)
		if err != nil {
			return true, err
		}
		a.Proxy.HTTPVersion = version
		return true, nil
	case "h2c":
		value, err := optionalBool(o)
		a.Proxy.H2C = value
		return true, err
	case "ignorecr":
		value, err := optionalBool(o)
		a.Proxy.IgnoreCR = value
		return true, err
	case "proxy-resolve":
		value, err := optionalBool(o)
		a.Proxy.Resolve = value
		return true, err
	case "proxy-authorization":
		if !o.Has {
			return true, nil
		}
		a.Proxy.Authorization = OptionalString{Set: true, Value: o.Value}
		return true, nil
	case "proxy-authorization-file":
		return true, decodeProtocolString(&a.Proxy.AuthorizationFile, o)
	case "socksport":
		return true, decodeProtocolString(&a.Proxy.SOCKSPort, o)
	case "socksuser":
		if !o.Has {
			return true, nil
		}
		a.Proxy.SOCKSUser = OptionalString{Set: true, Value: o.Value}
		return true, nil
	case "sockspass":
		if !o.Has {
			return true, nil
		}
		a.Proxy.SOCKSPassword = OptionalString{Set: true, Value: o.Value}
		return true, nil
	case "path":
		if !o.Has {
			return true, nil
		}
		a.WebSocket.Path = OptionalString{Set: true, Value: o.Value}
		return true, nil
	case "origin":
		if !o.Has {
			return true, nil
		}
		a.WebSocket.Origin = OptionalString{Set: true, Value: o.Value}
		return true, nil
	case "protocol":
		if a.Network.Kind == AddressKindSocket || a.Network.Kind == AddressKindVSOCK {
			return false, nil
		}
		if !o.Has {
			return true, nil
		}
		a.WebSocket.Protocol = OptionalString{Set: true, Value: o.Value}
		return true, nil
	}
	return false, nil
}

func decodeProtocolString(dst *OptionalString, o parse.Option) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	*dst = OptionalString{Set: true, Value: value}
	return nil
}

func decodeProtocolVersion(a *Address, o parse.Option, minimum bool) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	if a.Facts.Group == "Datagram TLS 1.3" {
		version, err := decodeDTLSVersion(value)
		if err != nil {
			return fmt.Errorf("%s: %w", optionIdentity(o), err)
		}
		if !minimum && version < 13 {
			return fmt.Errorf("%s: only DTLS 1.3 is supported", optionIdentity(o))
		}
		if minimum {
			a.DTLS.MinVersion = OptionalInt{Set: true, Value: version}
		} else {
			a.DTLS.MaxVersion = OptionalInt{Set: true, Value: version}
		}
		return nil
	}
	version, err := decodeTLSVersion(value)
	if err != nil {
		return fmt.Errorf("%s: %w", optionIdentity(o), err)
	}
	if minimum {
		a.TLS.MinVersion = version
	} else {
		a.TLS.MaxVersion = version
	}
	if a.TLS.MaxVersion != 0 && a.TLS.MinVersion > a.TLS.MaxVersion {
		return fmt.Errorf("minimum TLS protocol version exceeds maximum")
	}
	return nil
}

func decodeTLSVersion(value string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "TLS1", "TLS1.0", "TLSV1", "TLSV1.0":
		return tls.VersionTLS10, nil
	case "TLS1.1", "TLSV1.1":
		return tls.VersionTLS11, nil
	case "TLS1.2", "TLSV1.2":
		return tls.VersionTLS12, nil
	case "TLS1.3", "TLSV1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported protocol version %q", value)
	}
}

func decodeDTLSVersion(value string) (int, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "DTLS1", "DTLS1.0", "DTLSV1", "DTLSV1.0":
		return 10, nil
	case "DTLS1.2", "DTLSV1.2":
		return 12, nil
	case "DTLS1.3", "DTLSV1.3":
		return 13, nil
	default:
		return 0, fmt.Errorf("invalid DTLS protocol version %q", value)
	}
}

func decodeHTTPVersion(value string) (HTTPVersion, error) {
	switch strings.TrimSpace(value) {
	case "1.0", "":
		return HTTPVersion10, nil
	case "1.1":
		return HTTPVersion11, nil
	case "2":
		return HTTPVersion2, nil
	case "3":
		return HTTPVersion3, nil
	default:
		return 0, fmt.Errorf("http-version: invalid value %q", value)
	}
}

func decodeCipherSuites(value string) ([]uint16, error) {
	supported := make(map[string]uint16)
	for _, suite := range tls.CipherSuites() {
		for _, version := range suite.SupportedVersions {
			if version > tls.VersionTLS12 {
				continue
			}
			supported[strings.ToUpper(suite.Name)] = suite.ID
			opensslName := strings.TrimPrefix(suite.Name, "TLS_")
			opensslName = strings.Replace(opensslName, "_WITH_", "_", 1)
			opensslName = strings.ReplaceAll(opensslName, "AES_128", "AES128")
			opensslName = strings.ReplaceAll(opensslName, "AES_256", "AES256")
			opensslName = strings.ReplaceAll(opensslName, "_", "-")
			supported[strings.ToUpper(opensslName)] = suite.ID
			if shorter, ok := strings.CutSuffix(opensslName, "-SHA256"); ok && strings.Contains(shorter, "CHACHA20") {
				supported[strings.ToUpper(shorter)] = suite.ID
			}
			break
		}
	}
	names := strings.FieldsFunc(value, func(r rune) bool {
		return r == ':' || r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	if len(names) == 0 {
		return nil, fmt.Errorf("ciphers: empty cipher suite list")
	}
	seen := make(map[uint16]struct{}, len(names))
	out := make([]uint16, 0, len(names))
	for _, name := range names {
		suite, ok := supported[strings.ToUpper(name)]
		if !ok {
			return nil, fmt.Errorf("ciphers: cipher suite %q is not supported by Go's secure TLS policy", name)
		}
		if _, duplicate := seen[suite]; duplicate {
			continue
		}
		seen[suite] = struct{}{}
		out = append(out, suite)
	}
	return out, nil
}
