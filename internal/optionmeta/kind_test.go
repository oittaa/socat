package optionmeta

import "testing"

func TestLookupReportsForkKind(t *testing.T) {
	fork, ok := Lookup("fork")
	if !ok {
		t.Fatal("missing fork")
	}
	if fork.Kind != KindBool {
		t.Fatalf("fork kind %v", fork.Kind)
	}
}
