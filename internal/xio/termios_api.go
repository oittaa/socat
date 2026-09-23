package xio

import "github.com/oittaa/socat/internal/xio/termios"

// FeatureTERMIOS reports whether termios options are applied on this OS.
var FeatureTERMIOS = termios.FeatureTERMIOS

// TermiosHelpNames lists termios option spellings for help text.
func TermiosHelpNames() []string { return termios.TermiosHelpNames() }
