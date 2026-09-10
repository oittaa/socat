package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestIsolationOptionsRejectedByCLI(t *testing.T) {
	cases := []struct {
		left, right, spelling string
	}{
		{"TCP:127.0.0.1:1,setuid=65534", "STDOUT", "setuid"},
		{"STDOUT", "TCP:127.0.0.1:1,chroot=/tmp", "chroot"},
		{"STDIN,setgid=65534!!STDOUT", "STDOUT", "setgid"},
		{"TCP:127.0.0.1:1,su=65534", "PIPE", "su"},
		{"TCP:127.0.0.1:1,su-d=65534", "STDOUT", "su-d"},
		{"TCP:127.0.0.1:1,substuser-early=65534", "STDOUT", "substuser-early"},
		{"TCP:127.0.0.1:1,chroot-early=/tmp", "STDOUT", "chroot-early"},
		{"TCP:127.0.0.1:1,setuid-early=65534", "STDOUT", "setuid-early"},
	}
	for _, tc := range cases {
		t.Run(tc.left+"_"+tc.right, func(t *testing.T) {
			err := validateCLIAddresses(t, tc.left, tc.right)
			if err == nil || !strings.Contains(err.Error(), "not supported") || !strings.Contains(err.Error(), "isolation") {
				t.Fatalf("CLI validation error=%v", err)
			}
			if !strings.Contains(err.Error(), `option "`+tc.spelling+`"`) {
				t.Fatalf("error=%v want spelling %q", err, tc.spelling)
			}
		})
	}
}

func TestIsolationTypoRemainsUnknownAtCLI(t *testing.T) {
	err := validateCLIAddresses(t, "TCP:127.0.0.1:1,setuidd=65534", "STDOUT")
	if err == nil || !strings.Contains(err.Error(), "unknown option") {
		t.Fatalf("error=%v want unknown option", err)
	}
	if strings.Contains(err.Error(), "isolation") {
		t.Fatalf("typo treated as isolation option: %v", err)
	}
}

func validateCLIAddresses(t *testing.T, left, right string) error {
	t.Helper()
	lch, err := parse.ParseChannel(left)
	if err != nil {
		return err
	}
	if err := validateChannelOptions(lch); err != nil {
		return err
	}
	rch, err := parse.ParseChannel(right)
	if err != nil {
		return err
	}
	return validateChannelOptions(rch)
}

func TestFileOwnerUserIsNotIsolationOption(t *testing.T) {
	ch, err := parse.ParseChannel("CREATE:file,user=65534")
	if err != nil {
		t.Fatal(err)
	}
	err = validateChannelOptions(ch)
	if err != nil {
		t.Fatalf("user= is file owner, got %v", err)
	}
}

func TestHelpOmitsIsolationOptions(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{
		"setuid", "setuid-early", "setgid", "setgid-early",
		"chroot", "chroot-early", "substuser", "substuser-delayed",
		"substuser-early", "su-d",
	} {
		for _, line := range strings.Split(help, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == name {
				t.Errorf("help advertises %q: %s", name, strings.TrimSpace(line))
			}
		}
	}
}
