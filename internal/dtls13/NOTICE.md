# Pion attribution

The key derivation, AES record protection, and associated regression vectors
are adapted from https://github.com/pion/dtls at
`59f4c33b90c58fa6256a9cf1db49d1a9976b3536`, under the MIT license reproduced
in `LICENSE.pion`.

| Local file | Upstream source |
| --- | --- |
| `keys.go` | `pkg/crypto/keyschedule/keyschedule.go` |
| `protection.go` | `internal/ciphersuite/tls_13_record_protection.go` |
| `protection_test.go` | `internal/ciphersuite/tls_13_record_protection_test.go` |

The adaptation replaces upstream-specific builders/errors with standard Go.
ChaCha20-Poly1305 support uses golang.org/x/crypto. Connection, record framing,
and protocol state management belong to this package. Retain attribution when
moving these files.
