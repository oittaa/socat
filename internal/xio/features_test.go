package xio

import (
	"runtime"
	"testing"
)

func TestFeatureFlagsMatchOS(t *testing.T) {
	unix := runtime.GOOS != "windows"
	linux := runtime.GOOS == "linux"

	want := map[string]bool{
		"EXEC":          unix,
		"PTY":           unix,
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
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %v want %v (GOOS=%s)", name, got[name], w, runtime.GOOS)
		}
	}
}
