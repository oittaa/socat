package xio

import "testing"

func TestFeatureFlagsMatchOS(t *testing.T) {
	got := map[string]bool{
		"EXEC":          FeatureEXEC,
		"PTY":           FeaturePTY,
		"SOCKETPAIR":    FeatureSOCKETPAIR,
		"STALL":         FeatureSTALL,
		"GENERICSOCKET": FeatureGENERICSOCKET,
		"RAWIP":         FeatureRAWIP,
		"ABSTRACT":      FeatureABSTRACT,
		"TUN":           FeatureTUN,
		"INTERFACE":     FeatureINTERFACE,
		"NAMESPACES":    FeatureNAMESPACES,
		"TERMIOS":       FeatureTERMIOS,
	}
	for name, w := range expectedFeatureFlags() {
		if got[name] != w {
			t.Errorf("%s: got %v want %v", name, got[name], w)
		}
	}
}

func featureFlagExpectations(unix, linux, pty bool) map[string]bool {
	return map[string]bool{
		"EXEC":          unix,
		"PTY":           pty,
		"SOCKETPAIR":    unix,
		"STALL":         unix,
		"GENERICSOCKET": unix,
		"RAWIP":         unix,
		"ABSTRACT":      linux,
		"TUN":           linux,
		"INTERFACE":     linux,
		"NAMESPACES":    linux,
		"TERMIOS":       unix,
	}
}
