package testutil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestRuntimeUnixSocketTestsUseShortPaths prevents a regression to t.TempDir
// paths, whose test-name component can exceed Darwin's sockaddr_un limit.
func TestRuntimeUnixSocketTestsUseShortPaths(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate testutil package")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	fset := token.NewFileSet()
	for _, tree := range []string{"e2e", "internal"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, tree), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				fn, ok := node.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					return true
				}
				usesTempDir, createsUnixSocket, usesAdHocShortDir := inspectUnixSocketTest(fn.Body)
				if usesAdHocShortDir || usesTempDir && createsUnixSocket {
					position := fset.Position(fn.Pos())
					t.Errorf("%s:%d: %s must use testutil.UnixSocketPath", filepath.ToSlash(strings.TrimPrefix(path, repoRoot+string(filepath.Separator))), position.Line, fn.Name.Name)
				}
				return false
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func inspectUnixSocketTest(body *ast.BlockStmt) (usesTempDir, createsUnixSocket, usesAdHocShortDir bool) {
	unixAddress := false
	runtimeCall := false
	ast.Inspect(body, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				break
			}
			value, err := strconv.Unquote(node.Value)
			if err == nil && (strings.Contains(value, "UNIX-") || value == "unix" || value == "unixgram" || value == "unixpacket") {
				unixAddress = true
			}
		case *ast.CallExpr:
			selector, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				break
			}
			switch selector.Sel.Name {
			case "TempDir":
				usesTempDir = true
			case "Listen", "ListenUnixgram", "Dial", "DialUnix", "Command", "CommandContext", "OpenChannel":
				runtimeCall = true
			case "MkdirTemp":
				if len(node.Args) != 0 {
					if root, ok := node.Args[0].(*ast.BasicLit); ok && root.Kind == token.STRING && root.Value == `"/tmp"` {
						usesAdHocShortDir = true
					}
				}
			}
		}
		return true
	})
	return usesTempDir, unixAddress && runtimeCall, usesAdHocShortDir
}
