package main

import (
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Supported GOOS values. Everything else in Go's KnownOS list is rejected
// when it appears in a build constraint or a filename suffix.
var supportedOS = map[string]bool{
	"linux":   true,
	"darwin":  true,
	"windows": true,
}

// knownOS is Go's filename-matching OS list (go/internal/syslist.KnownOS)
// minus the three supported targets. unix is not in this list: Go does not
// treat *_unix.go as an implicit unix tag.
var unsupportedOS = map[string]bool{
	"aix":       true,
	"android":   true,
	"dragonfly": true,
	"freebsd":   true,
	"hurd":      true,
	"illumos":   true,
	"ios":       true,
	"js":        true,
	"nacl":      true,
	"netbsd":    true,
	"openbsd":   true,
	"plan9":     true,
	"solaris":   true,
	"wasip1":    true,
	"zos":       true,
}

type finding struct {
	Path string
	Line int
	Msg  string
}

func (f finding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", f.Path, f.Line, f.Msg)
	}
	return fmt.Sprintf("%s: %s", f.Path, f.Msg)
}

func findModuleRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", start)
		}
		dir = parent
	}
}

func scanTree(root string) ([]finding, error) {
	var out []finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { // #nosec G703 -- walks the module tree from go.mod, not a user path
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			// testdata/vendor plus Go's package-discovery skip of . and _ dirs
			// (.codex-review-*, _scratch, .git, …).
			if name == "testdata" || name == "vendor" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		hits, err := scanFile(rel, path)
		if err != nil {
			return err
		}
		out = append(out, hits...)
		return nil
	})
	return out, err
}

func scanFile(rel, abs string) ([]finding, error) {
	src, err := os.ReadFile(abs) // #nosec G304 -- abs is a *.go path produced by WalkDir under the module root
	if err != nil {
		return nil, err
	}
	var out []finding
	out = append(out, filenameFindings(rel)...)
	hits, err := constraintFindings(rel, src)
	if err != nil {
		return nil, err
	}
	out = append(out, hits...)
	return out, nil
}

func filenameFindings(rel string) []finding {
	base := filepath.Base(rel)
	name, _, _ := strings.Cut(base, ".")
	i := strings.Index(name, "_")
	if i < 0 {
		return nil
	}
	parts := strings.Split(name[i:], "_") // leading empty from the '_'
	if n := len(parts); n > 0 && parts[n-1] == "test" {
		parts = parts[:n-1]
	}
	n := len(parts)
	if n == 0 {
		return nil
	}
	var tag string
	switch {
	case n >= 2 && unsupportedOS[parts[n-2]] && knownArch[parts[n-1]]:
		tag = parts[n-2]
	case unsupportedOS[parts[n-1]]:
		tag = parts[n-1]
	default:
		return nil
	}
	return []finding{{
		Path: rel,
		Msg:  fmt.Sprintf("filename suffix implies unsupported GOOS %s", tag),
	}}
}

// knownArch is Go's filename-matching arch list (go/internal/syslist.KnownArch).
var knownArch = map[string]bool{
	"386": true, "amd64": true, "amd64p32": true,
	"arm": true, "armbe": true, "arm64": true, "arm64be": true,
	"loong64": true,
	"mips":    true, "mipsle": true, "mips64": true, "mips64le": true,
	"mips64p32": true, "mips64p32le": true,
	"ppc": true, "ppc64": true, "ppc64le": true,
	"riscv": true, "riscv64": true,
	"s390": true, "s390x": true,
	"sparc": true, "sparc64": true, "wasm": true,
}

func constraintFindings(rel string, src []byte) ([]finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.PackageClauseOnly|parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	pkgLine := fset.Position(f.Package).Line
	var out []finding
	for _, cg := range f.Comments {
		if fset.Position(cg.Pos()).Line >= pkgLine {
			continue
		}
		for _, c := range cg.List {
			text := c.Text
			if !strings.HasPrefix(text, "//go:build") && !strings.HasPrefix(text, "// +build") {
				continue
			}
			expr, err := constraint.Parse(text)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", rel, fset.Position(c.Pos()).Line, err)
			}
			line := fset.Position(c.Pos()).Line
			out = append(out, walkConstraint(rel, line, expr, false)...)
		}
	}
	return out, nil
}

func walkConstraint(rel string, line int, expr constraint.Expr, negated bool) []finding {
	switch e := expr.(type) {
	case *constraint.TagExpr:
		return tagFindings(rel, line, e.Tag, negated)
	case *constraint.NotExpr:
		return walkConstraint(rel, line, e.X, !negated)
	case *constraint.AndExpr:
		return append(walkConstraint(rel, line, e.X, negated), walkConstraint(rel, line, e.Y, negated)...)
	case *constraint.OrExpr:
		return append(walkConstraint(rel, line, e.X, negated), walkConstraint(rel, line, e.Y, negated)...)
	default:
		return nil
	}
}

func tagFindings(rel string, line int, tag string, negated bool) []finding {
	switch {
	case tag == "unix":
		msg := "build constraint uses unix; list linux, darwin, and/or windows"
		if negated {
			msg = "build constraint uses !unix"
		}
		return []finding{{Path: rel, Line: line, Msg: msg}}
	case unsupportedOS[tag]:
		return []finding{{Path: rel, Line: line, Msg: fmt.Sprintf("build constraint uses %s", tag)}}
	case negated && supportedOS[tag]:
		return []finding{{Path: rel, Line: line, Msg: fmt.Sprintf("build constraint uses !%s", tag)}}
	default:
		return nil
	}
}
