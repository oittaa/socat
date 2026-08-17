//go:build windows

package main

import "io"

func printLinuxSockopts(io.Writer, int) {}

func socketProtocol(int) (int, error) { return -1, nil }
