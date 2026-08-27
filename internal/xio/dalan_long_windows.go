//go:build windows

package xio

// Windows uses LLP64: C long remains 32 bits on 64-bit targets.
const sizeCLong = 4
