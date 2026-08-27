package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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
//   - ancillary recv pairs (both spellings): xio/ip_ancillary_matrix.go and
//     xio/ancillary.go NeedAncillary / ApplyAncillaryRecvOpts
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
	"ippktinfo": "xio/ancillary.go", "iprecvttl": "xio/ancillary.go",
	"iprecvtos": "xio/ancillary.go", "iprecvopts": "xio/ancillary.go",

	"ip-ttl": "xio/ip_ancillary_send.go", "ip-tos": "xio/ip_ancillary_send.go",
	"ip-options": "xio/ip_ancillary_send.go", "ipoptions": "xio/ip_ancillary_send.go",
	"ipv6-unicast-hops": "xio/ip_ancillary_send.go", "ipv6-tclass": "xio/ip_ancillary_send.go",
	"ttl": "xio/ip_ancillary_send.go", "tos": "xio/ip_ancillary_send.go",
	"ipttl": "xio/ip_ancillary_send.go", "iptos": "xio/ip_ancillary_send.go",
	"unicast-hops": "xio/ip_ancillary_send.go", "tclass": "xio/ip_ancillary_send.go",

	"setlk": "fileopen/lock.go", "setlkw": "fileopen/lock.go",
	"setlk-rd": "fileopen/lock.go", "setlkw-rd": "fileopen/lock.go",

	// Canonical/alias families selected by last-option-wins helper loops.
	"so-linger": "xio/options.go", "linger": "xio/options.go",
	"o-noatime": "xio/options.go", "noatime": "xio/options.go",
	"f-setpipe-sz": "xio/options.go", "pipesz": "xio/options.go",
	"children-shutup": "xio/options.go", "child-shutup": "xio/options.go",
	"openssl-min-proto-version": "tlsopen/tls.go",
	"openssl-max-proto-version": "tlsopen/tls.go",
	"so-protocol":               "netopen/vsock.go parseVsockProtocolOption",

	"perm": "xio/run.go", "mode": "xio/run.go",
	"user": "xio/fdopts_lifecycle.go", "uid": "xio/fdopts_lifecycle.go", "owner": "xio/fdopts_lifecycle.go",
	"group": "xio/fdopts_lifecycle.go", "gid": "xio/fdopts_lifecycle.go",
	"ftruncate32": "xio/fdopts_lifecycle.go", "ftruncate64": "xio/fdopts_lifecycle.go",

	// PH_PREOPEN NAMED walk in ApplyNamedPreopen (command-line order).
	"perm-early": "xio/named_preopen.go", "user-early": "xio/named_preopen.go",
	"group-early": "xio/named_preopen.go", "unlink": "xio/named_preopen.go",

	// PH_PASTSOCKET membership walk in option order (not last-wins).
	"ip-add-membership": "xio/mcast_opt.go membershipJoins",
	"ipv6-join-group":   "xio/mcast_opt.go membershipJoins",
}

// compatNoOptions are advertised deliberately as classic-compat spellings
// whose acceptance is the feature; nothing reads them.
// recognizedUnsupportedOptions are deliberately accepted so the relevant
// opener can return a precise "not supported" error; helpOptionGroups keeps the
// authoritative list and routes them to that error.
var recognizedUnsupportedOptions = map[string]string{
	"openssl-method":      "stream TLS only; rejected with a precise error",
	"openssl-fips":        "Go crypto/tls has no OpenSSL FIPS module",
	"openssl-compress":    "Go crypto/tls has no TLS compression",
	"openssl-egd":         "Go does not use EGD for randomness",
	"openssl-pseudo":      "Go crypto/tls does not use OpenSSL pseudo-random bytes",
	"openssl-dhparam":     "Go crypto/tls does not load DH parameters",
	"openssl-maxfraglen":  "Go crypto/tls has no max fragment length option",
	"openssl-maxsendfrag": "Go crypto/tls has no max send fragment option",
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

// termiosFamilyNames collects the platform's dynamic termios option names, so
// the contract follows the same build-tagged tables as the CLI.
func termiosFamilyNames(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range xio.TermiosHelpNames() {
		out[parse.CanonicalOptionName(name)] = "xio.TermiosHelpNames"
	}
	// These common help spellings remain visible on platforms where termios is
	// unavailable; the address opener rejects the unsupported PTY at runtime.
	for _, name := range []string{"cfmakeraw", "raw", "rawer", "sane", "echo", "opost", "winsz", "waitslave"} {
		out[name] = "common termios help"
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
