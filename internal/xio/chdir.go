package xio

import (
	"os"
	"sync"

	"github.com/oittaa/socat/internal/parse"
)

// chdirMu serializes process-wide chdir around address open (fork uses goroutines).
var chdirMu sync.Mutex

// WithChdir runs fn with the process cwd set to chdir= (classic per-address).
// The previous directory is restored afterward so the other address is unaffected.
func WithChdir(s parse.Spec, fn func() error) error {
	if !s.HasOption("chdir") {
		return fn()
	}
	o, ok := s.OptionNamed("chdir")
	if !ok || !o.Has || o.Value == "" {
		return fn()
	}
	chdirMu.Lock()
	defer chdirMu.Unlock()
	old, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := os.Chdir(o.Value); err != nil {
		return err
	}
	defer func() { _ = os.Chdir(old) }()
	return fn()
}
