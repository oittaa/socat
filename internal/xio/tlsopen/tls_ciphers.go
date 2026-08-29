// TLS cipher-list translation: OpenSSL-style names to Go TLS 1.0-1.2 suites.
package tlsopen

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// applyCipherSuites translates OpenSSL cipher-list names to Go's configurable
// TLS 1.0-1.2 suites. TLS 1.3 suites stay under crypto/tls (ciphers= does not set them).
func applyCipherSuites(cfg *tls.Config, s parse.Spec) error {
	value := strings.TrimSpace(s.OptionValue("ciphers", ""))
	if value == "" {
		return nil
	}

	supported := make(map[string]uint16)
	for _, suite := range tls.CipherSuites() {
		configurable := false
		for _, version := range suite.SupportedVersions {
			if version <= tls.VersionTLS12 {
				configurable = true
				break
			}
		}
		if !configurable {
			continue
		}
		supported[strings.ToUpper(suite.Name)] = suite.ID
		opensslName := strings.TrimPrefix(suite.Name, "TLS_")
		opensslName = strings.Replace(opensslName, "_WITH_", "_", 1)
		opensslName = strings.ReplaceAll(opensslName, "AES_128", "AES128")
		opensslName = strings.ReplaceAll(opensslName, "AES_256", "AES256")
		opensslName = strings.ReplaceAll(opensslName, "_", "-")
		supported[strings.ToUpper(opensslName)] = suite.ID
		// OpenSSL omits the redundant SHA256 suffix on its ChaCha20 names.
		if shorter, ok := strings.CutSuffix(opensslName, "-SHA256"); ok && strings.Contains(shorter, "CHACHA20") {
			supported[strings.ToUpper(shorter)] = suite.ID
		}
	}

	names := strings.FieldsFunc(value, func(r rune) bool {
		return r == ':' || r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	if len(names) == 0 {
		return fmt.Errorf("ciphers: empty cipher suite list")
	}
	ids := make([]uint16, 0, len(names))
	seen := make(map[uint16]struct{}, len(names))
	for _, name := range names {
		id, ok := supported[strings.ToUpper(name)]
		if !ok {
			return fmt.Errorf("ciphers: cipher suite %q is not supported by Go's secure TLS policy", name)
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	cfg.CipherSuites = ids
	return nil
}
