package cli

import (
	"os"
	"path/filepath"
	"reflect"
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
