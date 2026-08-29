//go:build linux || darwin

package xio

import "strconv"

// Linux and macOS use a word-sized C long.
const sizeCLong = strconv.IntSize / 8
