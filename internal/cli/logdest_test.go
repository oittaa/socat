package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestParseArgsAcceptsSAsNoOp(t *testing.T) {
	withS, err := ParseArgs([]string{"-s", "STDIN", "STDOUT"})
	if err != nil {
		t.Fatal(err)
	}
	withoutS, err := ParseArgs([]string{"STDIN", "STDOUT"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(withS, withoutS) {
		t.Fatalf("-s changed config: with=%+v without=%+v", withS, withoutS)
	}
}

func TestParseArgsRejectsG(t *testing.T) {
	_, err := ParseArgs([]string{"-g", "STDIN", "STDOUT"})
	if err == nil || err.Error() != `option "-g" is not implemented` {
		t.Fatalf("-g: %v", err)
	}
}

func TestParseArgsRejectsUnknownFacility(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	_, err := ParseArgs([]string{"-lynotafacility", "STDIN", "STDOUT"})
	if err == nil || !strings.Contains(err.Error(), `unknown syslog facility "notafacility"`) {
		t.Fatalf("err=%v", err)
	}
}

func TestParseArgsWindowsRejectsSyslogAndDump(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip()
	}
	for _, flag := range []string{"-ly", "-lylocal0", "-lm", "-lmlocal0", "-D"} {
		_, err := ParseArgs([]string{flag, "STDIN", "STDOUT"})
		want := "-ly"
		switch {
		case strings.HasPrefix(flag, "-lm"):
			want = "-lm"
		case flag == "-D":
			want = "-D"
		}
		if err == nil || err.Error() != `option "`+want+`" is not implemented` {
			t.Fatalf("%s: %v", flag, err)
		}
	}
}

func TestParseArgsDumpFDUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	cfg, err := ParseArgs([]string{"-D", "STDIN", "STDOUT"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DumpFDs {
		t.Fatal("DumpFDs not set")
	}
}

func TestSetupLoggerLastWinsFileThenStderr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "socat.log")
	cfg, err := ParseArgs([]string{"-lf", path, "-ls", "STDIN", "STDOUT"})
	if err != nil {
		t.Fatal(err)
	}
	log, closeLog, err := setupLogger(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeLog)
	log.Errorf("hello")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("log file should not be created: %v", err)
	}
}
