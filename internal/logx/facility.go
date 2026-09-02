package logx

import (
	"fmt"
	"strings"
)

// DefaultFacility is used when -ly or -lm omit a facility name.
const DefaultFacility = "daemon"

var syslogFacilities = map[string]struct{}{
	"auth":     {},
	"authpriv": {},
	"cron":     {},
	"daemon":   {},
	"ftp":      {},
	"kern":     {},
	"local0":   {},
	"local1":   {},
	"local2":   {},
	"local3":   {},
	"local4":   {},
	"local5":   {},
	"local6":   {},
	"local7":   {},
	"lpr":      {},
	"mail":     {},
	"news":     {},
	"syslog":   {},
	"user":     {},
	"uucp":     {},
}

// CanonicalFacility returns the lowercase syslog facility name.
// An omitted name means daemon. Unknown names are rejected.
func CanonicalFacility(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return DefaultFacility, nil
	}
	lower := strings.ToLower(name)
	if _, ok := syslogFacilities[lower]; !ok {
		return "", fmt.Errorf("unknown syslog facility %q", name)
	}
	return lower, nil
}
