package addrconfig

import (
	"reflect"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestSplitExecArgs(t *testing.T) {
	got := splitExecArgs(`prog "a b" "" c`)
	if !reflect.DeepEqual(got, []string{"prog", "a b", "", "c"}) {
		t.Fatalf("quoted=%q", got)
	}
	got = splitExecArgs(`prog "say \"hi\""`)
	if !reflect.DeepEqual(got, []string{"prog", `say "hi"`}) {
		t.Fatalf("escaped=%q", got)
	}
	got = splitExecArgs("echo  hello\tworld")
	if !reflect.DeepEqual(got, []string{"echo", "hello", "world"}) {
		t.Fatalf("spaces=%q", got)
	}
}

func TestDecodeEXECArgv(t *testing.T) {
	got := decodeProcess(t, "EXEC:echo hello", AddressKindEXEC)
	if !reflect.DeepEqual(got.Process.Argv, []string{"echo", "hello"}) {
		t.Fatalf("argv=%q", got.Process.Argv)
	}
	if got.Process.Command != "" || got.Process.HasCommand {
		t.Fatalf("EXEC must not keep a shell command: %+v", got.Process)
	}
}

func TestDecodeEXECQuotedAndEmptyArgs(t *testing.T) {
	got, err := Decode(parse.Spec{Type: "EXEC", Params: []string{`prog "a b" "" c`}}, Facts{Type: "EXEC", Kind: AddressKindEXEC})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Process.Argv, []string{"prog", "a b", "", "c"}) {
		t.Fatalf("quoted argv=%q", got.Process.Argv)
	}

	got, err = Decode(parse.Spec{Type: "EXEC", Params: []string{`prog "say \"hi\""`}}, Facts{Type: "EXEC", Kind: AddressKindEXEC})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Process.Argv, []string{"prog", `say "hi"`}) {
		t.Fatalf("escaped quote argv=%q", got.Process.Argv)
	}

	quoted := decodeProcess(t, `EXEC:"echo hello"`, AddressKindEXEC)
	if !reflect.DeepEqual(quoted.Process.Argv, []string{"echo", "hello"}) {
		t.Fatalf("quoted address argv=%q", quoted.Process.Argv)
	}
}

func TestDecodeSYSTEMAndSHELLStayShellCommands(t *testing.T) {
	system := decodeProcess(t, "SYSTEM:echo hello", AddressKindSYSTEM)
	if system.Process.Command != "echo hello" || !system.Process.HasCommand {
		t.Fatalf("SYSTEM command=%+v", system.Process)
	}
	if len(system.Process.Argv) != 0 {
		t.Fatalf("SYSTEM argv=%q want empty", system.Process.Argv)
	}

	shell := decodeProcess(t, "SHELL:echo hi", AddressKindSHELL)
	if shell.Process.Command != "echo hi" || !shell.Process.HasCommand {
		t.Fatalf("SHELL command=%+v", shell.Process)
	}
	if len(shell.Process.Argv) != 0 {
		t.Fatalf("SHELL argv=%q want empty", shell.Process.Argv)
	}

	interactive := decodeProcess(t, "SHELL", AddressKindSHELL)
	if interactive.Process.HasCommand || interactive.Process.Command != "" {
		t.Fatalf("interactive SHELL=%+v", interactive.Process)
	}
}

func decodeProcess(t *testing.T, text string, kind AddressKind) Address {
	t.Helper()
	spec, err := parse.ParseSpec(text)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(spec, Facts{Type: spec.Type, Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	return got
}
