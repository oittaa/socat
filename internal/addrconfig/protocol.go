package addrconfig

import (
	"crypto/tls"
	"fmt"
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

// TLSUnsupported is the last occurrence of one unsupported TLS option.
type TLSUnsupported struct {
	Canonical string
	Name      string
	Reason    string
	Reject    bool
	Index     int
}

func recordTLSPlaintextName(a *Address, o parse.Option, definition optionmeta.Option) {
	spelling := o.OriginalSpelling()
	if spelling == "" {
		spelling = o.Name
	}
	if definition.Hidden && definition.TLSRejectReason != "" {
		a.TLS.LastHiddenName = spelling
		a.TLS.LastPlaintextName = spelling
		return
	}
	if definition.PublicTLS {
		a.TLS.LastPlaintextName = spelling
	}
}

func decodeProtocolVersion(a *Address, o parse.Option, minimum bool) error {
	value, err := requiredString(o)
	if err != nil {
		return err
	}
	if a.Facts.Kind == AddressKindDTLS {
		version, err := decodeDTLSVersion(value)
		if err != nil {
			return optionValueError(o, "invalid value", err.Error())
		}
		if !minimum && version < 13 {
			return optionValueError(o, "invalid value", "only DTLS 1.3 is supported")
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
		return optionValueError(o, "invalid value", err.Error())
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
