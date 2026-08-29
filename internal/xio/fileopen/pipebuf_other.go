//go:build darwin || windows

package fileopen

import "os"

func pipeBufSize(*os.File) int { return 65536 }
