package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// Option-table contract: the CLI table and the option lookups performed by
// the address implementations must agree in both directions.
//
// History justifying this test: keepidle was implemented but rejected by the
// CLI, addrconfig was accepted but silently ignored, sndtimeo was canonicalized
// but rejected by the option table, and ptmx/openpty carried compat semantics
// that only classic test.sh exposed. Each class is caught here mechanically.

// dynamicallyReadOptions are canonical names looked up through literal slices
// in the implementations rather than inline string arguments, so AST scanning
// cannot see them. Each entry points at its consuming table:
//
//   - termios flags/bauds and PTY controls: xio/termios.go termiosFlags,
//     baudNamed, TermiosHelpNames
//   - iff-* interface flags: tunopen/tun_linux.go parseIffOpts
//   - tcpwrap family: xio/tcpwrap.go parseTCPWrap name loop
//   - ancillary recv pairs (both spellings): xio/ancillary.go NeedAncillary /
//     ApplyAncillaryRecvOpts
//   - whole-file locks: fileopen/lock.go applyFileLocks
var dynamicallyReadOptions = map[string]string{
	// termios flag/baud/control names are merged in at runtime from
	// xio/termios.go (see termiosFamilyNames) — too many to mirror by hand.

	"iff-up": "tunopen/tun_linux.go", "iff-broadcast": "tunopen/tun_linux.go",
	"iff-debug": "tunopen/tun_linux.go", "iff-loopback": "tunopen/tun_linux.go",
	"iff-pointopoint": "tunopen/tun_linux.go", "iff-running": "tunopen/tun_linux.go",
	"iff-noarp": "tunopen/tun_linux.go", "iff-promisc": "tunopen/tun_linux.go",
	"iff-allmulti": "tunopen/tun_linux.go", "iff-multicast": "tunopen/tun_linux.go",
	"iff-no-pi": "tunopen/tun_linux.go",
	// Short classic aliases of the iff-* family (same dynamic consumer).
	"up": "tunopen/tun_linux.go", "loopback": "tunopen/tun_linux.go",
	"pointopoint": "tunopen/tun_linux.go", "running": "tunopen/tun_linux.go",
	"noarp": "tunopen/tun_linux.go", "promisc": "tunopen/tun_linux.go",
	"allmulti": "tunopen/tun_linux.go",
	// Short spellings of the ancillary recv pairs (same dynamic consumer).
	"timestamp": "xio/ancillary.go", "pktinfo": "xio/ancillary.go",
	"recvttl": "xio/ancillary.go", "recvtos": "xio/ancillary.go",
	"recvopts": "xio/ancillary.go", "recvpktinfo": "xio/ancillary.go",
	"recvtclass": "xio/ancillary.go", "recvhoplimit": "xio/ancillary.go",

	"tcpwrap": "xio/tcpwrap.go", "tcpwrappers": "xio/tcpwrap.go",
	"tcpwrapper": "xio/tcpwrap.go", "libwrap": "xio/tcpwrap.go",
	"wrap": "xio/tcpwrap.go",

	"so-timestamp": "xio/ancillary.go", "ip-pktinfo": "xio/ancillary.go",
	"ip-recvttl": "xio/ancillary.go", "ip-recvtos": "xio/ancillary.go",
	"ip-recvopts": "xio/ancillary.go", "ipv6-recvpktinfo": "xio/ancillary.go",
	"ipv6-recvhoplimit": "xio/ancillary.go", "ipv6-recvtclass": "xio/ancillary.go",

	"setlk": "fileopen/lock.go", "setlkw": "fileopen/lock.go",
	"setlk-rd": "fileopen/lock.go", "setlkw-rd": "fileopen/lock.go",
}

// compatNoOptions are advertised deliberately as classic-compat spellings
// whose acceptance is the feature; nothing reads them.
// recognizedUnsupportedOptions are deliberately accepted so the relevant
// opener can return a precise "not supported" error; options.go keeps the
// authoritative list and routes them to that error.
var recognizedUnsupportedOptions = map[string]string{
	"openssl-method": "stream TLS only; rejected with a precise error",
	"opensslmethod":  "stream TLS only; rejected with a precise error",
}

var compatNoOptions = map[string]string{
	"ptmx":    "classic compat: /dev/ptmx is the platform default",
	"openpty": "classic compat: openpty(3) semantics are the default",
}

type consumedSite struct {
	pkg  string
	name string
}

// collectConsumedOptionNames AST-scans every non-test Go file under dir for
// Spec option lookups (OptionValue/BoolOption/HasOption/OptionNamed) whose
// first argument is a string literal, and returns their canonical names.
func collectConsumedOptionNames(t *testing.T, dir string) map[string][]consumedSite {
	t.Helper()
	out := map[string][]consumedSite{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			var sel *ast.SelectorExpr
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				sel = fn
			default:
				return true
			}
			switch sel.Sel.Name {
			case "OptionValue", "BoolOption", "HasOption", "OptionNamed":
			default:
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			raw := strings.Trim(lit.Value, `"`)
			canonical := parse.CanonicalOptionName(raw)
			pkg := f.Name.Name
			out[canonical] = append(out[canonical], consumedSite{pkg: pkg, name: raw})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}
	return out
}

// termiosFamilyNames extracts the option names of xio/termios.go's
// termiosFlags and baudNamed tables (each entry's first string literal) plus
// the raw-mode control spellings, so the contract covers the whole family
// without mirroring dozens of entries by hand.
func termiosFamilyNames(t *testing.T) map[string]string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "xio", "termios.go"))
	if err != nil {
		t.Fatalf("read termios.go: %v", err)
	}
	out := map[string]string{}
	for _, table := range []string{"termiosFlags", "baudNamed"} {
		loc := regexp.MustCompile(`\b` + table + `\s*[:=]`).FindStringIndex(string(src))
		if loc == nil {
			t.Fatalf("table %q not found in termios.go", table)
		}
		i := loc[0]
		first := strings.Index(string(src)[i:], `{"`)
		if first < 0 {
			t.Fatalf("no entries found for table %q", table)
		}
		end := strings.Index(string(src)[i+first:], "\n}")
		if end < 0 {
			t.Fatalf("unterminated table %q", table)
		}
		block := string(src[i+first : i+first+end])
		for _, m := range regexp.MustCompile(`\{"([a-z0-9]+)"`).FindAllStringSubmatch(block, -1) {
			out[m[1]] = "xio/termios.go " + table
		}
	}
	for _, extra := range []string{"cfmakeraw", "raw", "rawer", "sane", "winsz", "waitslave"} {
		out[extra] = "xio/termios.go controls"
	}
	return out
}

func TestOptionTableContract(t *testing.T) {
	xioDir := filepath.Join("..", "xio")
	consumed := collectConsumedOptionNames(t, xioDir)
	table := buildSupportedAddressOptions()
	termiosNames := termiosFamilyNames(t)

	tableCanonical := make(map[string]struct{}, len(table))
	for name := range table {
		tableCanonical[parse.CanonicalOptionName(name)] = struct{}{}
	}

	// Direction A: every option an implementation looks up must be accepted.
	var missing []string
	for name := range consumed {
		if _, ok := table[name]; !ok {
			sites := consumed[name]
			sort.Slice(sites, func(i, j int) bool { return sites[i].pkg < sites[j].pkg })
			missing = append(missing, name+" (e.g. "+sites[0].pkg+")")
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("options consumed by implementations but rejected by the CLI table; add them to helpOptionGroups or fix the consumer:\n  %s",
			strings.Join(missing, "\n  "))
	}

	// Direction B: every advertised option must be consumed somewhere —
	// literally, via a dynamic-name family, or as a documented compat no-op.
	var unconsumed []string
	for name := range tableCanonical {
		if _, ok := consumed[name]; ok {
			continue
		}
		if _, ok := dynamicallyReadOptions[name]; ok {
			continue
		}
		if _, ok := termiosNames[name]; ok {
			continue
		}
		if _, ok := compatNoOptions[name]; ok {
			continue
		}
		if _, ok := recognizedUnsupportedOptions[name]; ok {
			continue
		}
		unconsumed = append(unconsumed, name)
	}
	if len(unconsumed) > 0 {
		sort.Strings(unconsumed)
		t.Errorf("advertised options with no implementation consumer; implement, fold into dynamicallyReadOptions, or list in compatNoOptions:\n  %s",
			strings.Join(unconsumed, "\n  "))
	}

	// Direction C: options restricted to protocol-specific address groups
	// must be consumed only inside the matching implementation packages.
	pkgToGroup := map[string]string{
		"tlsopen":     xio.GroupTLS,
		"wsopen":      xio.GroupWebSocket,
		"proxyopen":   xio.GroupProxy,
		"posixmqopen": xio.GroupPOSIXMQ,
		"tunopen":     xio.GroupTUN,
		"quicopen":    xio.GroupQUIC,
	}
	for name, entry := range table {
		if len(entry.addressGroups) == 0 {
			continue
		}
		sites := consumed[name]
		for _, site := range sites {
			group, known := pkgToGroup[site.pkg]
			if !known {
				t.Errorf("group-restricted option %q consumed in package %q (not a protocol package)", name, site.pkg)
				continue
			}
			allowed := false
			for _, g := range entry.addressGroups {
				if g == group {
					allowed = true
					break
				}
			}
			if !allowed {
				t.Errorf("option %q (%v) consumed in package %q (group %q)", name, entry.addressGroups, site.pkg, group)
			}
		}
	}

	// Guard canaries: representatives of each dynamic family must stay covered
	// on both sides, so silent table edits cannot strand a whole family.
	canaries := []string{"iff-up", "setlk", "tcpwrap", "ip-pktinfo"}
	for _, c := range canaries {
		if _, ok := table[c]; !ok {
			t.Errorf("dynamic-family canary %q missing from the option table", c)
		}
		if _, ok := dynamicallyReadOptions[c]; !ok {
			t.Errorf("dynamic-family canary %q missing from dynamicallyReadOptions", c)
		}
	}
	if len(xio.TermiosHelpNames()) > 0 {
		for _, c := range []string{"b115200", "icanon"} {
			if _, ok := termiosNames[c]; !ok {
				t.Errorf("termios-family canary %q missing from implementation tables", c)
			}
			if _, ok := table[c]; !ok {
				t.Errorf("termios-family canary %q missing from the option table", c)
			}
		}
	}
}
