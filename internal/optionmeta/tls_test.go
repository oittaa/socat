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

func TestTLSRejectReasonsIncludeAdvertisedCompress(t *testing.T) {
	reasons := TLSRejectReasons()
	if reasons["openssl-compress"] == "" || reasons["openssl-method"] == "" {
		t.Fatalf("%v", reasons)
	}
}
