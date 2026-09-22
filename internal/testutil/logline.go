package testutil

import (
	"regexp"
	"strings"
)

// diagnosticSeverity matches the severity letter on a diagnostic line.
var diagnosticSeverity = regexp.MustCompile(`\[[0-9]+\] ([FEDWNI]) `)

// DiagnosticLevels reports which severity letters appear on lines that
// mention needle.
func DiagnosticLevels(text, needle string) map[string]bool {
	out := map[string]bool{}
	if needle == "" {
		return out
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		m := diagnosticSeverity.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out[m[1]] = true
	}
	return out
}
