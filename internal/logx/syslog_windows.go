//go:build windows

package logx

import "fmt"

func defaultSyslogDial(string, string) (SyslogWriter, error) {
	return nil, fmt.Errorf("syslog is not implemented")
}
