//go:build unix && !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package xio

// No unix.B7200 on this Unix (Solaris, AIX, z/OS, …). Do not advertise b7200.
var platformBaudNamed []baudOption
