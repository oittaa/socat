package optionmeta

import "testing"

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
