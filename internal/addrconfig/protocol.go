package addrconfig

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

// TLS holds static TLS settings. Certificate and CA paths remain live inputs.
type TLS struct {
	Certificate            OptionalString
	Key                    OptionalString
	CAFile                 OptionalString
	CAPath                 OptionalString
	Verify                 OptionalBool
	CommonName             OptionalString
	SNIHost                OptionalString
	NoSNI                  OptionalBool
	CipherSuites           []uint16
	MinVersion             uint16
	MaxVersion             uint16
	ALPN                   OptionalString
	LastHiddenName         string
	LastPlaintextName      string
	UnsupportedSet         bool
	UnsupportedCanonical   string
	UnsupportedName        string
	UnsupportedReason      string
	DTLSMTU                OptionalInt
	DTLSMigration          OptionalBool
	DTLSUnfragmentedProbes OptionalBool
	DTLSMinVersion         OptionalInt
	DTLSMaxVersion         OptionalInt
	WSPath                 OptionalString
	WSOrigin               OptionalString
	WSProtocol             OptionalString
}

// HTTPVersion selects a CONNECT transport.
type HTTPVersion uint8

const (
	HTTPVersion10 HTTPVersion = iota + 1
	HTTPVersion11
	HTTPVersion2
	HTTPVersion3
)

// TLSUnsupported is the last occurrence of one unsupported TLS option.
type TLSUnsupported struct {
	Canonical string
	Name      string
	Reason    string
	Reject    bool
	Index     int
}

// Proxy holds static HTTP CONNECT and SOCKS settings.
type Proxy struct {
	Server            HostTarget
	Target            HostTarget
	TargetPort        PortTarget
	EndpointsSet      bool
	Port              PortTarget
	PortSet           bool
	HTTPVersion       HTTPVersion
	H2C               OptionalBool
	IgnoreCR          OptionalBool
	Resolve           OptionalBool
	Authorization     OptionalString
	AuthorizationFile OptionalString
	SOCKSPort         PortTarget
	SOCKSPortSet      bool
	SOCKSUser         OptionalString
	SOCKSPassword     OptionalString
}

func decodeProtocolOption(d *decoder, o parse.Option, name string) (bool, error) {
	a := &d.Address
	recordTLSPlaintextName(a, o, name)
	if def, ok := optionmeta.Lookup(name); ok && def.TLSRejectReason != "" {
		if err := decodeUnsupportedTLSValue(name, o); err != nil {
			return true, err
		}
		recordUnsupportedTLS(d, name, o, def.TLSRejectReason, !compatibleDisabledTLSOption(name, o))
		return true, nil
	}
	switch name {
	case "cert":
		return true, setOptionText(&a.TLS.Certificate, o)
	case "key":
		return true, setOptionText(&a.TLS.Key, o)
	case "cafile":
		return true, setOptionText(&a.TLS.CAFile, o)
	case "capath":
		return true, setOptionText(&a.TLS.CAPath, o)
	case "verify":
		return true, setActive(&a.TLS.Verify, o)
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
		return true, setActive(&a.TLS.NoSNI, o)
	case "ciphers":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		value = strings.TrimSpace(value)
		if value == "" {
			a.TLS.CipherSuites = nil
			return true, nil
		}
		suites, err := decodeCipherSuites(value)
		if err != nil {
			return true, err
		}
		a.TLS.CipherSuites = suites
		return true, nil
	case "openssl-min-proto-version":
		return true, decodeProtocolVersion(a, o, name, true)
	case "openssl-max-proto-version":
		return true, decodeProtocolVersion(a, o, name, false)
	case "alpn":
		value := optionText(o)
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
		a.TLS.DTLSMTU = OptionalInt{Set: true, Value: value}
		return true, nil
	case "dtls-migration", "dtls-unfragmented-probes":
		value, err := optionalBool(o)
		if name == "dtls-migration" {
			a.TLS.DTLSMigration = value
		} else {
			a.TLS.DTLSUnfragmentedProbes = value
		}
		return true, err
	case "proxyport":
		a.Proxy.Port = portTarget(optionText(o))
		a.Proxy.PortSet = true
		return true, nil
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
		return true, setActive(&a.Proxy.H2C, o)
	case "ignorecr":
		return true, setActive(&a.Proxy.IgnoreCR, o)
	case "proxy-resolve":
		return true, setActive(&a.Proxy.Resolve, o)
	case "proxy-authorization":
		if !o.Has {
			return true, nil
		}
		a.Proxy.Authorization = OptionalString{Set: true, Value: o.Value}
		return true, nil
	case "proxy-authorization-file":
		return true, setOptionText(&a.Proxy.AuthorizationFile, o)
	case "socksport":
		a.Proxy.SOCKSPort = portTarget(optionText(o))
		a.Proxy.SOCKSPortSet = true
		return true, nil
	case "socksuser":
		a.Proxy.SOCKSUser = OptionalString{Set: true, Value: optionText(o)}
		return true, nil
	case "sockspass":
		a.Proxy.SOCKSPassword = OptionalString{Set: true, Value: optionText(o)}
		return true, nil
	case "path", "origin":
		opt := OptionalString{Set: true, Value: optionText(o)}
		if name == "path" {
			a.TLS.WSPath = opt
		} else {
			a.TLS.WSOrigin = opt
		}
		return true, nil
	case "protocol":
		if a.Network.Kind == AddressKindSocket || a.Network.Kind == AddressKindVSOCK {
			return false, nil
		}
		a.TLS.WSProtocol = OptionalString{Set: true, Value: optionText(o)}
		return true, nil
	}
	return false, nil
}

func recordTLSPlaintextName(a *Address, o parse.Option, name string) {
	def, ok := optionmeta.Lookup(name)
	if !ok {
		return
	}
	spelling := o.OriginalSpelling()
	if spelling == "" {
		spelling = o.Name
	}
	if def.Hidden && def.TLSRejectReason != "" {
		a.TLS.LastHiddenName = spelling
		a.TLS.LastPlaintextName = spelling
		return
	}
	if def.PublicTLS {
		a.TLS.LastPlaintextName = spelling
	}
}

func compatibleDisabledTLSOption(name string, o parse.Option) bool {
	switch name {
	case "openssl-fips", "openssl-pseudo":
		v, err := optionalBool(o)
		return err == nil && !v.Value
	case "openssl-compress":
		return o.Has && strings.EqualFold(strings.TrimSpace(o.Value), "none")
	default:
		return false
	}
}

func decodeUnsupportedTLSValue(name string, o parse.Option) error {
	switch name {
	case "openssl-method", "openssl-egd", "openssl-dhparam", "openssl-compress":
		_, err := requiredString(o)
		return err
	case "openssl-fips", "openssl-pseudo":
		_, err := optionalBool(o)
		return err
	case "openssl-maxfraglen", "openssl-maxsendfrag":
		if !o.Has {
			return nil
		}
		_, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
		if err != nil {
			return fmt.Errorf("invalid %s %q", o.OriginalSpelling(), o.Value)
		}
		return nil
	default:
		return nil
	}
}

func setOptionText(dst *OptionalString, o parse.Option) error {
	*dst = OptionalString{Set: true, Value: optionText(o)}
	return nil
}

func decodeProtocolVersion(a *Address, o parse.Option, name string, minimum bool) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	if a.Facts.Kind == AddressKindDTLS {
		version, err := decodeDTLSVersion(value)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if !minimum && version < 13 {
			return fmt.Errorf("%s: only DTLS 1.3 is supported", name)
		}
		if minimum {
			a.TLS.DTLSMinVersion = OptionalInt{Set: true, Value: version}
		} else {
			a.TLS.DTLSMaxVersion = OptionalInt{Set: true, Value: version}
		}
		return nil
	}
	version, err := decodeTLSVersion(value)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if minimum {
		a.TLS.MinVersion = version
	} else {
		a.TLS.MaxVersion = version
	}
	return nil
}

func recordUnsupportedTLS(d *decoder, canonical string, o parse.Option, reason string, reject bool) {
	spelling := o.OriginalSpelling()
	if spelling == "" {
		spelling = o.Name
	}
	state := TLSUnsupported{
		Canonical: canonical,
		Name:      spelling,
		Reason:    reason,
		Reject:    reject,
		Index:     d.optionIndex,
	}
	for i := range d.unsupported {
		if d.unsupported[i].Canonical == canonical {
			d.unsupported[i] = state
			return
		}
	}
	d.unsupported = append(d.unsupported, state)
}

func resolveUnsupportedTLS(d *decoder) {
	last := -1
	d.TLS.UnsupportedSet = false
	d.TLS.UnsupportedCanonical = ""
	d.TLS.UnsupportedName = ""
	d.TLS.UnsupportedReason = ""
	for _, option := range d.unsupported {
		if option.Reject && option.Index >= last {
			last = option.Index
			d.TLS.UnsupportedSet = true
			d.TLS.UnsupportedCanonical = option.Canonical
			d.TLS.UnsupportedName = option.Name
			d.TLS.UnsupportedReason = option.Reason
		}
	}
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
