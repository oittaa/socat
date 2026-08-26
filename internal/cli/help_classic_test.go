package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpDoesNotTriggerClassicOptionArraySentinel(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	// Classic test.sh uses the loose expression /opt:/ as an internal-help
	// sentinel. Human-readable descriptions must not accidentally match it.
	if strings.Contains(output.String(), "opt:") {
		t.Fatal("-hhh output contains classic test.sh's internal option-array sentinel \"opt:\"")
	}
}

func TestHelpListsSoBroadcastAlias(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	for _, name := range []string{"broadcast", "so-broadcast"} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("-hhh missing %q", name)
		}
	}
	if !strings.Contains(help, "alias of broadcast") {
		t.Error("-hhh missing so-broadcast alias line")
	}
}

func TestHelpListsDescriptorLifecycleAliases(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	help := output.String()
	for _, name := range []string{"perm", "user", "group", "ftruncate"} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("-hhh missing canonical %q", name)
		}
	}
	aliases := map[string]string{
		"mode":        "perm",
		"uid":         "user",
		"owner":       "user",
		"gid":         "group",
		"truncate":    "ftruncate",
		"ftruncate32": "ftruncate",
		"ftruncate64": "ftruncate",
	}
	for alias, canon := range aliases {
		want := "alias of " + canon
		found := false
		for _, line := range strings.Split(help, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == alias && strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("-hhh missing %q as %s", alias, want)
		}
	}
}
