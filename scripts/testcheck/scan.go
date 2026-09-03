package main

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

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
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { // #nosec G703 -- walks the module tree from go.mod
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if name == "testdata" || name == "vendor" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		hits, err := scanTestFile(rel, path)
		if err != nil {
			return err
		}
		out = append(out, hits...)
		return nil
	})
	return out, err
}

func isPlatformSpecificFile(rel string, src []byte) bool {
	base := filepath.Base(rel)
	for _, suffix := range []string{
		"_windows_test.go",
		"_unix_test.go",
		"_linux_test.go",
		"_darwin_test.go",
	} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//go:build") {
			continue
		}
		expr, err := constraint.Parse(line)
		if err == nil {
			s := expr.String()
			if strings.Contains(s, "linux") || strings.Contains(s, "darwin") || strings.Contains(s, "windows") {
				return true
			}
		}
	}
	return false
}

func scanTestFile(rel, abs string) ([]finding, error) {
	src, err := os.ReadFile(abs) // #nosec G304 -- abs is a *_test.go path under the module root
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	platformSpecific := isPlatformSpecificFile(rel, src)
	var out []finding

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Skip" && len(node.Args) == 0 {
					pos := fset.Position(node.Pos())
					out = append(out, finding{
						Path: rel,
						Line: pos.Line,
						Msg:  "bare t.Skip() prohibited; provide an explicit explanation",
					})
				}
			}
		case *ast.IfStmt:
			if !platformSpecific && isRuntimeGOOSSkip(node) {
				pos := fset.Position(node.Pos())
				out = append(out, finding{
					Path: rel,
					Line: pos.Line,
					Msg:  "runtime GOOS skip prohibited in cross-platform test file; use build tags or platform-specific test files",
				})
			}
		}
		return true
	})

	return out, nil
}

func isRuntimeGOOSSkip(stmt *ast.IfStmt) bool {
	if !containsRuntimeGOOS(stmt.Cond) {
		return false
	}
	hasSkip := false
	ast.Inspect(stmt.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" {
					hasSkip = true
					return false
				}
			}
		}
		return true
	})
	return hasSkip
}

func containsRuntimeGOOS(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "runtime" && sel.Sel.Name == "GOOS" {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}
