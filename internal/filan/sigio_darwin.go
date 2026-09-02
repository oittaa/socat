//go:build darwin

package filan

import "github.com/oittaa/socat/internal/outbuf"

func appendSigioHeader(*outbuf.Buf) {}

func appendSigio(*outbuf.Buf, int) {}
