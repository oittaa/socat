//go:build linux || darwin

package logx

import "log/syslog"

func defaultSyslogDial(tag string, facility Facility) (SyslogWriter, error) {
	w, err := syslog.New(facilityPriority(facility)|syslog.LOG_INFO, tag)
	if err != nil {
		return nil, err
	}
	return w, nil
}

func facilityPriority(facility Facility) syslog.Priority {
	switch facility {
	case FacilityKern:
		return syslog.LOG_KERN
	case FacilityUser:
		return syslog.LOG_USER
	case FacilityMail:
		return syslog.LOG_MAIL
	case FacilityAuth:
		return syslog.LOG_AUTH
	case FacilitySyslog:
		return syslog.LOG_SYSLOG
	case FacilityLPR:
		return syslog.LOG_LPR
	case FacilityNews:
		return syslog.LOG_NEWS
	case FacilityUUCP:
		return syslog.LOG_UUCP
	case FacilityCron:
		return syslog.LOG_CRON
	case FacilityAuthpriv:
		return syslog.LOG_AUTHPRIV
	case FacilityFTP:
		return syslog.LOG_FTP
	case FacilityLocal0:
		return syslog.LOG_LOCAL0
	case FacilityLocal1:
		return syslog.LOG_LOCAL1
	case FacilityLocal2:
		return syslog.LOG_LOCAL2
	case FacilityLocal3:
		return syslog.LOG_LOCAL3
	case FacilityLocal4:
		return syslog.LOG_LOCAL4
	case FacilityLocal5:
		return syslog.LOG_LOCAL5
	case FacilityLocal6:
		return syslog.LOG_LOCAL6
	case FacilityLocal7:
		return syslog.LOG_LOCAL7
	default:
		return syslog.LOG_DAEMON
	}
}
