package optionmeta

import "testing"

func TestUnsupportedTLSFamilies(t *testing.T) {
	opts := UnsupportedTLS()
	if len(opts) != 7 || opts[0].Canonical != "openssl-method" || opts[0].TLSRejectReason != "stream TLS only" {
		t.Fatalf("%+v", opts)
	}
	if opts[1].CLIValue != OptionalBool || opts[5].CLIValue != OptionalSignedInteger {
		t.Fatalf("value kinds %+v", opts)
	}
}

func TestUnsupportedTLSCopiesAliases(t *testing.T) {
	a := UnsupportedTLS()
	a[0].Aliases[0] = "mutated"
	if UnsupportedTLS()[0].Aliases[0] != "opensslmethod" {
		t.Fatal("catalog alias slice was shared")
	}
}

func TestValidateUnsupportedTLS(t *testing.T) {
	opts := UnsupportedTLS()
	opts[0].Canonical = ""
	if err := validateUnsupportedTLS(opts); err == nil {
		t.Fatal("empty canonical")
	}
	opts = UnsupportedTLS()
	opts[0].CLIValue = 0
	if err := validateUnsupportedTLS(opts); err == nil {
		t.Fatal("unknown value kind")
	}
}
