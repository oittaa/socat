package parse

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/classiccatalog"
)

func TestGoAliasesWhoseClassicGroupsDifferFromCanonical(t *testing.T) {
	// Parse must not fold a spelling onto a runtime name whose classic
	// groups/phases differ (ipv6-join-group is GROUP_IP6; ip-add-membership
	// is IP4+IP6). Validation uses OriginalSpelling. Keep this set empty.
	want := map[string]string{}
	got := map[string]string{}
	for spelling, canonical := range optionAliases {
		se, sok := classiccatalog.Lookup(spelling)
		ce, cok := classiccatalog.Lookup(canonical)
		if !sok || !cok {
			continue
		}
		if reflect.DeepEqual(se.Groups, ce.Groups) && se.Phase == ce.Phase {
			continue
		}
		got[spelling] = canonical
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("aliases whose classic groups/phases differ from the Go canonical target:\n  got  %s\n  want %s", formatAliasMap(got), formatAliasMap(want))
	}
}

func formatAliasMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"->"+m[k])
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ", ")
}
