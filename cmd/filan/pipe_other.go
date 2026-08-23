//go:build unix && !linux

package main

import "github.com/oittaa/socat/internal/outbuf"

func printPipeSize(int, *outbuf.Buf) {}
