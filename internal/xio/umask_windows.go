//go:build windows

package xio

import "github.com/oittaa/socat/internal/parse"

func WithUmask(_ parse.Spec, fn func() error) error { return fn() }
