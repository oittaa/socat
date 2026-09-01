package fileopen

import (
	"os"
	"runtime"
	"sync"
)

// inheritedFiles keeps os.File wrappers for FD addresses reachable for the
// process lifetime. Closing those wrappers would close the caller's
// descriptor; dropping them would leave a stale runtime poller entry.
var inheritedFiles struct {
	mu    sync.Mutex
	files []*os.File
}

func retainInheritedFile(f *os.File) {
	runtime.SetFinalizer(f, nil)
	inheritedFiles.mu.Lock()
	inheritedFiles.files = append(inheritedFiles.files, f)
	inheritedFiles.mu.Unlock()
}
