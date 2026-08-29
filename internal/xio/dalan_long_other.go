//go:build linux || darwin

package xio

import "strconv"

// Classic's supported non-Windows ABIs use a word-sized C long.
const sizeCLong = strconv.IntSize / 8
