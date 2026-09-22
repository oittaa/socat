package parse

import "testing"

func TestAddressSlashEscapes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: `TEXT:a\0b`, want: "a\x00b"},
		{in: `TEXT:a\ab`, want: "a\ab"},
		{in: `TEXT:a\bb`, want: "a\bb"},
		{in: `TEXT:a\eb`, want: "aeb"},
		{in: `TEXT:a\fb`, want: "a\fb"},
		{in: `TEXT:a\nb`, want: "a\nb"},
		{in: `TEXT:a\rb`, want: "a\rb"},
		{in: `TEXT:a\tb`, want: "a\tb"},
		{in: `TEXT:a\vb`, want: "a\vb"},
		{in: `TEXT:a\\b`, want: `a\b`},
		{in: `TEXT:a\x41b`, want: "aAb"},
		{in: `TEXT:a\x4ab`, want: "aJb"},
		{in: `TEXT:a\x4Ab`, want: "aJb"},
		{in: `TEXT:a\x00b`, want: "a\x00b"},
		{in: `TEXT:"a\n"`, want: "a\n"},
		{in: `TEXT:'a\t'`, want: "a\t"},
		{in: `TEXT:a\:b`, want: "a:b"},
		{in: `TEXT:a\,b`, want: "a,b"},
		{in: `TEXT:a\qb`, want: "aqb"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			spec, err := ParseSpec(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(spec.Params) != 1 || spec.Params[0] != tc.want {
				t.Fatalf("params %#v want %#q", spec.Params, tc.want)
			}
		})
	}
}

func TestEscapedTrailingSpace(t *testing.T) {
	spec, err := ParseSpec("TEXT:a\\ ")
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Params) != 1 || spec.Params[0] != "a " {
		t.Fatalf("params %#v", spec.Params)
	}
	ch, err := ParseChannel("TEXT:a\\ ")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Single == nil || len(ch.Single.Params) != 1 || ch.Single.Params[0] != "a " {
		t.Fatalf("channel params %#v", ch.Single)
	}

	spec, err = ParseSpec("TCP:h:1,bind=a\\ ,fork")
	if err != nil {
		t.Fatal(err)
	}
	if got := optionValue(spec, "bind", ""); got != "a " {
		t.Fatalf("bind %#q", got)
	}
	if !hasOption(spec, "fork") {
		t.Fatal("missing fork")
	}

	spec, err = ParseSpec("TEXT:a ")
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Params) != 1 || spec.Params[0] != "a" {
		t.Fatalf("unescaped trailing space params %#v", spec.Params)
	}
}

func TestOptionValueSlashEscape(t *testing.T) {
	spec, err := ParseSpec(`TCP:h:1,bind=a\nb`)
	if err != nil {
		t.Fatal(err)
	}
	if got := optionValue(spec, "bind", ""); got != "a\nb" {
		t.Fatalf("bind %#q", got)
	}
}

func TestMalformedSlashEscapesRejected(t *testing.T) {
	// \x1g used to become byte 0x01 and drop the following g.
	cases := []string{
		`TEXT:a\x1gb`,
		`TEXT:a\x1g`,
		`TEXT:a\x1`,
		`TEXT:a\x`,
		`TEXT:a\xgg`,
		`TEXT:a\xG1`,
		`TEXT:a\`,
		`TEXT:"a\x1gb"`,
		`TCP:h:1,bind=a\x1gb`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			spec, err := ParseSpec(in)
			if err == nil {
				t.Fatalf("accepted %#v", spec)
			}
		})
	}
}

func TestImplicitFDRequiresASCIIDigits(t *testing.T) {
	spec, err := ParseSpec("10")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Type != "FD" || len(spec.Params) != 1 || spec.Params[0] != "10" {
		t.Fatalf("got %+v", spec)
	}
	// Unicode decimal digits must not select an FD address.
	for _, in := range []string{"٣", "３", "1٣"} {
		spec, err := ParseSpec(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if spec.Type == "FD" {
			t.Errorf("%q parsed as FD: %+v", in, spec)
		}
	}
}
