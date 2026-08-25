package xio

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestClassicAllowsOptionAmbiguousAliases(t *testing.T) {
	if !ClassicAllowsOption("TCP", "noatime") {
		t.Fatal(`ClassicAllowsOption("TCP", "noatime") must be true; optionnames[] maps noatime to opt_o_noatime (open|fd)`)
	}
	if !ClassicAllowsOption("UDP4", "pktinfo") {
		t.Fatal(`ClassicAllowsOption("UDP4", "pktinfo") must be true; optionnames[] maps pktinfo to opt_ip_pktinfo (IPv4+IPv6)`)
	}
}

func TestExtractClassicGroupsOptionnamesWinOverNicknames(t *testing.T) {
	script, py := extractClassicGroupsTool(t)
	dir := t.TempDir()
	writeClassicFile(t, dir, "xio-aaa.c", `
const struct optdesc opt_fs_noatime = { "fs-noatime", "noatime", 1, GROUP_REG, 0, 0, 0 };
const struct optdesc opt_ipv6_pktinfo = { "ipv6-pktinfo", "pktinfo", 1, GROUP_SOCK_IP6, 0, 0, 0 };
`)
	writeClassicFile(t, dir, "xio-zzz.c", `
const struct optdesc opt_o_noatime = { "o-noatime", "noatime", 1, GROUP_OPEN|GROUP_FD, 0, 0, 0 };
const struct optdesc opt_ip_pktinfo = { "ip-pktinfo", "pktinfo", 1, GROUP_SOCK_IP, 0, 0, 0 };
`)
	writeClassicFile(t, dir, "xioopts.c", `
const struct optname optionnames[] = {
	IF_OPEN   ("noatime",	&opt_o_noatime)
	IF_IP     ("pktinfo",	&opt_ip_pktinfo)
	{ NULL }
};
`)
	writeClassicFile(t, dir, "xioopen.c", `
const struct addrname addressnames[] = {
	{ NULL }
};
`)
	out := runExtractClassicGroups(t, py, script, dir)
	if !strings.Contains(out, `"noatime": []string{"open", "fd"}`) {
		t.Fatalf("noatime must follow optionnames[] -> opt_o_noatime:\n%s", out)
	}
	if !strings.Contains(out, `"pktinfo": []string{"sock-ip4", "sock-ip6"}`) {
		t.Fatalf("pktinfo must follow optionnames[] -> opt_ip_pktinfo:\n%s", out)
	}
	if strings.Contains(out, `"noatime": []string{"reg"}`) {
		t.Fatal("noatime must not take the fs-noatime nickname groups")
	}
}

func TestExtractClassicGroupsMatchesOfficialCheckout(t *testing.T) {
	script, py := extractClassicGroupsTool(t)
	src := cloneOfficialSocat(t)
	first := gofmtSource(t, runExtractClassicGroups(t, py, script, src))
	second := gofmtSource(t, runExtractClassicGroups(t, py, script, src))
	if first != second {
		t.Fatal("regenerating twice from the same official checkout produced different output")
	}
	want, err := os.ReadFile("classicgroups_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if first != string(want) {
		t.Fatal("generated output differs from checked-in classicgroups_gen.go; regenerate from https://repo.or.cz/socat.git tag-1.8.1.3")
	}
}

func gofmtSource(t *testing.T, src string) string {
	t.Helper()
	cmd := exec.Command("gofmt")
	cmd.Stdin = strings.NewReader(src)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("gofmt: %v", err)
	}
	return string(out)
}

func extractClassicGroupsTool(t *testing.T) (script, python string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	script = filepath.Join(filepath.Dir(file), "../../scripts/extract-classic-groups.py")
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return script, p
		}
	}
	t.Skip("python3 is required to run the classic group generator")
	return "", ""
}

func runExtractClassicGroups(t *testing.T, python, script, src string) string {
	t.Helper()
	cmd := exec.Command(python, script, src)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("extract-classic-groups.py: %v\n%s", err, stderr.String())
	}
	return stdout.String()
}

func writeClassicFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func cloneOfficialSocat(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required to clone official socat")
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", "tag-1.8.1.3",
		"https://repo.or.cz/socat.git", dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("clone official socat tag-1.8.1.3: %v\n%s", err, stderr.String())
	}
	return dir
}
