package cli

import (
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/classiccatalog"
)

func advertisedHelpNames(all bool) map[string]struct{} {
	out := map[string]struct{}{}
	for _, group := range helpOptionGroups() {
		if hideOptGroup(group.title) {
			continue
		}
		for _, option := range group.opts {
			if hideOpt(option.name) {
				continue
			}
			out[option.name] = struct{}{}
			if all {
				for _, alias := range option.aliases {
					out[alias] = struct{}{}
				}
			}
		}
	}
	for _, name := range extraHelpNames(all) {
		out[name] = struct{}{}
	}
	return out
}

func TestCatalogVsGoHelp(t *testing.T) {
	advertised := advertisedHelpNames(true)
	var extra []string
	for name := range advertised {
		if _, ok := classiccatalog.Lookup(name); ok {
			continue
		}
		if _, ok := classiccatalog.GoOnlyHelpAllowlist[name]; ok {
			continue
		}
		extra = append(extra, name)
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Fatalf("Go -hhh advertises names not in the classic catalog and not on GoOnlyHelpAllowlist: %s",
			strings.Join(extra, ", "))
	}

	var stale, unadvertised []string
	for name := range classiccatalog.GoOnlyHelpAllowlist {
		if _, ok := classiccatalog.Lookup(name); ok {
			stale = append(stale, name)
		}
		if _, ok := advertised[name]; !ok {
			unadvertised = append(unadvertised, name)
		}
	}
	sort.Strings(stale)
	sort.Strings(unadvertised)
	if len(stale) > 0 {
		t.Errorf("GoOnlyHelpAllowlist names that are in the classic catalog: %s", strings.Join(stale, ", "))
	}
	if runtime.GOOS == "linux" && len(unadvertised) > 0 {
		t.Errorf("GoOnlyHelpAllowlist names not advertised in this build's -hhh: %s", strings.Join(unadvertised, ", "))
	}

	var missing []string
	for spelling := range classiccatalog.Options {
		if _, ok := advertised[spelling]; !ok {
			missing = append(missing, spelling)
		}
	}
	sort.Strings(missing)
	t.Logf("classic catalog spellings not advertised in Go -hhh: %d (expected until later compatibility PRs)", len(missing))
}
