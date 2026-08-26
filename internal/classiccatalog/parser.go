package classiccatalog

import (
	"fmt"
	"regexp"
	"strings"
)

// Address aliases print "is an alias name for"; option aliases omit "name".
var (
	// Classic help pads with tabs; long GROUP_IPAPP lists can glue into "UDPLITEphase=".
	optionDetailRE = regexp.MustCompile(`^\s{6}(\S+)\s+groups=(\S+?)(?:\s*)phase=(\S+)\s+type=(\S+)\s*$`)
	optionAliasRE  = regexp.MustCompile(`^\s{6}(\S+)\s+is an alias for (\S+)\s*$`)
)

// ParseHHHOptions extracts the advertised option catalog from classic
// `socat -hhh` output (full help text or the `opts:` section).
func ParseHHHOptions(text string) (map[string]Entry, error) {
	section, err := optionSection(text)
	if err != nil {
		return nil, err
	}
	details := map[string]Entry{}
	type alias struct{ spelling, canonical string }
	var aliases []alias
	seen := map[string]struct{}{}
	for _, line := range strings.Split(section, "\n") {
		if m := optionDetailRE.FindStringSubmatch(line); m != nil {
			spelling := m[1]
			if _, dup := seen[spelling]; dup {
				continue
			}
			seen[spelling] = struct{}{}
			details[spelling] = Entry{
				Spelling:  spelling,
				Canonical: spelling,
				Groups:    strings.Split(m[2], ","),
				Phase:     m[3],
				Type:      m[4],
			}
			continue
		}
		if m := optionAliasRE.FindStringSubmatch(line); m != nil {
			spelling, canonical := m[1], m[2]
			if _, dup := seen[spelling]; dup {
				continue
			}
			seen[spelling] = struct{}{}
			aliases = append(aliases, alias{spelling, canonical})
		}
	}
	out := make(map[string]Entry, len(details)+len(aliases))
	for spelling, e := range details {
		out[spelling] = e
	}
	var missing []string
	for _, a := range aliases {
		src, ok := details[a.canonical]
		if !ok {
			missing = append(missing, a.spelling+"->"+a.canonical)
			continue
		}
		out[a.spelling] = Entry{
			Spelling:  a.spelling,
			Canonical: a.canonical,
			Groups:    src.Groups,
			Phase:     src.Phase,
			Type:      src.Type,
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("alias targets missing from -hhh details: %s", strings.Join(missing, ", "))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no option entries parsed from -hhh dump")
	}
	return out, nil
}

func optionSection(text string) (string, error) {
	if strings.HasPrefix(text, "   opts:") {
		return text, nil
	}
	const marker = "\n   opts:"
	if i := strings.Index(text, marker); i >= 0 {
		return text[i+1:], nil
	}
	return "", fmt.Errorf("classic -hhh dump has no 'opts:' section")
}
