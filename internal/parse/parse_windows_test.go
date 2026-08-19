//go:build windows

package parse

import "testing"

func TestParseWindowsRelativePath(t *testing.T) {
	path := `sub\temp.txt`
	ch, err := ParseChannel("CREATE:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Single.Params) != 1 || ch.Single.Params[0] != path {
		t.Fatalf("params %q", ch.Single.Params)
	}
}

func TestParseWindowsRelativeCertOption(t *testing.T) {
	cert := `certs\test.pem`
	s, err := ParseSpec("TLS-LISTEN:443,cert=" + cert)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.OptionValue("cert", ""); got != cert {
		t.Fatalf("cert %q", got)
	}
}

func TestParseWindowsBareRelativePath(t *testing.T) {
	path := `sub\temp.txt`
	ch, err := ParseChannel(path)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single.Type != "GOPEN" || len(ch.Single.Params) != 1 || ch.Single.Params[0] != path {
		t.Fatalf("got %+v", ch.Single)
	}
}
