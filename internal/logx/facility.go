package logx

import (
	"fmt"
	"strings"
)

// Facility is a syslog facility parsed from -ly or -lm.
type Facility uint8

const (
	FacilityDaemon Facility = iota
	FacilityAuth
	FacilityAuthpriv
	FacilityCron
	FacilityFTP
	FacilityKern
	FacilityLocal0
	FacilityLocal1
	FacilityLocal2
	FacilityLocal3
	FacilityLocal4
	FacilityLocal5
	FacilityLocal6
	FacilityLocal7
	FacilityLPR
	FacilityMail
	FacilityNews
	FacilitySyslog
	FacilityUser
	FacilityUUCP
)

var syslogFacilities = map[string]Facility{
	"auth":     FacilityAuth,
	"authpriv": FacilityAuthpriv,
	"cron":     FacilityCron,
	"daemon":   FacilityDaemon,
	"ftp":      FacilityFTP,
	"kern":     FacilityKern,
	"local0":   FacilityLocal0,
	"local1":   FacilityLocal1,
	"local2":   FacilityLocal2,
	"local3":   FacilityLocal3,
	"local4":   FacilityLocal4,
	"local5":   FacilityLocal5,
	"local6":   FacilityLocal6,
	"local7":   FacilityLocal7,
	"lpr":      FacilityLPR,
	"mail":     FacilityMail,
	"news":     FacilityNews,
	"syslog":   FacilitySyslog,
	"user":     FacilityUser,
	"uucp":     FacilityUUCP,
}

// ParseFacility returns the syslog facility for -ly/-lm.
// An omitted name means daemon. Unknown names are rejected.
func ParseFacility(name string) (Facility, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return FacilityDaemon, nil
	}
	f, ok := syslogFacilities[strings.ToLower(name)]
	if !ok {
		return 0, fmt.Errorf("unknown syslog facility %q", name)
	}
	return f, nil
}
