package optionmeta

import (
	"reflect"
	"strings"
	"testing"
)

func TestUnsupportedTLSContract(t *testing.T) {
	want := []UnsupportedTLSOption{
		{
			Canonical:       "openssl-method",
			Aliases:         []string{"opensslmethod", "method"},
			CLIValue:        RequiredString,
			TLSRejectReason: "stream TLS only",
		},
		{
			Canonical:       "openssl-fips",
			Aliases:         []string{"fips"},
			CLIValue:        OptionalBool,
			TLSRejectReason: "Go crypto/tls has no OpenSSL FIPS module",
		},
		{
			Canonical:       "openssl-egd",
			Aliases:         []string{"egd"},
			CLIValue:        RequiredString,
			TLSRejectReason: "Go does not use EGD for randomness",
		},
		{
			Canonical:       "openssl-pseudo",
			Aliases:         []string{"pseudo"},
			CLIValue:        OptionalBool,
			TLSRejectReason: "Go crypto/tls does not use OpenSSL pseudo-random bytes",
		},
		{
			Canonical:       "openssl-dhparam",
			Aliases:         []string{"openssl-dhparams", "dhparam", "dhparams", "dh"},
			CLIValue:        RequiredString,
			TLSRejectReason: "Go crypto/tls does not load DH parameters",
		},
		{
			Canonical:       "openssl-maxfraglen",
			Aliases:         []string{"maxfraglen"},
			CLIValue:        OptionalSignedInteger,
			TLSRejectReason: "Go crypto/tls has no max fragment length option",
		},
		{
			Canonical:       "openssl-maxsendfrag",
			Aliases:         []string{"maxsendfrag"},
			CLIValue:        OptionalSignedInteger,
			TLSRejectReason: "Go crypto/tls has no max send fragment option",
		},
	}
	got := UnsupportedTLS()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnsupportedTLS() mismatch\ngot  %#v\nwant %#v", got, want)
	}
	n := 0
	for _, opt := range want {
		n += 1 + len(opt.Aliases)
	}
	if n != 18 {
		t.Fatalf("spelling count=%d want 18", n)
	}
}

func TestUnsupportedTLSReturnsIndependentSlices(t *testing.T) {
	a := UnsupportedTLS()
	b := UnsupportedTLS()
	if len(a) == 0 || len(a[0].Aliases) == 0 {
		t.Fatal("expected aliases")
	}
	a[0].Canonical = "mutated"
	a[0].Aliases[0] = "mutated"
	if b[0].Canonical != "openssl-method" || b[0].Aliases[0] != "opensslmethod" {
		t.Fatalf("mutation leaked: %+v", b[0])
	}
	again := UnsupportedTLS()
	if again[0].Canonical != "openssl-method" || again[0].Aliases[0] != "opensslmethod" {
		t.Fatalf("catalog mutated: %+v", again[0])
	}
}

func TestValidateUnsupportedTLSRejectsInvalidDeclarations(t *testing.T) {
	valid := UnsupportedTLS()
	cases := []struct {
		name string
		mut  func([]UnsupportedTLSOption) []UnsupportedTLSOption
		want string
	}{
		{
			name: "empty canonical",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[0].Canonical = ""
				return opts
			},
			want: "empty canonical name",
		},
		{
			name: "uppercase canonical",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[0].Canonical = "OpenSSL-method"
				return opts
			},
			want: "non-lowercase canonical name",
		},
		{
			name: "duplicate canonical",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[1].Canonical = opts[0].Canonical
				opts[1].Aliases = []string{"other-alias"}
				return opts
			},
			want: "duplicate canonical name",
		},
		{
			name: "duplicate alias",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[1].Aliases = append(opts[1].Aliases, opts[0].Aliases[0])
				return opts
			},
			want: "duplicate alias",
		},
		{
			name: "alias repeats canonical",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[0].Aliases = append(opts[0].Aliases, opts[0].Canonical)
				return opts
			},
			want: "alias repeats canonical name",
		},
		{
			name: "alias collides with canonical",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[1].Aliases = []string{opts[0].Canonical}
				return opts
			},
			want: "collides with a canonical name",
		},
		{
			name: "empty alias",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[0].Aliases[0] = ""
				return opts
			},
			want: "empty alias name",
		},
		{
			name: "uppercase alias",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[0].Aliases[0] = "Method"
				return opts
			},
			want: "non-lowercase alias name",
		},
		{
			name: "empty reason",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[0].TLSRejectReason = ""
				return opts
			},
			want: "empty TLS reject reason",
		},
		{
			name: "unknown value kind",
			mut: func(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
				opts[0].CLIValue = 0
				return opts
			},
			want: "unknown CLI value kind",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := copyUnsupportedTLS(valid)
			err := validateUnsupportedTLS(tc.mut(opts))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want %q", err, tc.want)
			}
		})
	}
}
