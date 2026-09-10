//go:build linux

package xio

// TIOCINQ / FIONREAD. x/sys/unix exports TIOCINQ only on Linux.
func fionreadRequest() uint { return 0x541b }
