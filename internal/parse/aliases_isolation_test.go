package parse

import "testing"

func TestIsolationAliasesFoldOntoCanonicalNames(t *testing.T) {
	if got := CanonicalOptionName("su"); got != "substuser" {
		t.Fatalf("CanonicalOptionName(su)=%q want substuser", got)
	}
	if got := CanonicalOptionName("su-d"); got != "substuser-delayed" {
		t.Fatalf("CanonicalOptionName(su-d)=%q want substuser-delayed", got)
	}
	if got := CanonicalOptionName("user"); got != "user" {
		t.Fatalf("CanonicalOptionName(user)=%q want user", got)
	}
}
