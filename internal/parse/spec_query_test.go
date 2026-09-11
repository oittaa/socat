package parse

import "strings"

// Parser tests inspect last-wins option storage. Execution reads
// addrconfig.Address, not these helpers.

func optionNamed(s Spec, name string) (Option, bool) {
	name = normalizeOptionName(name)
	for i := len(s.Options) - 1; i >= 0; i-- {
		o := s.Options[i]
		if normalizeOptionName(o.Name) == name {
			return o, true
		}
	}
	return Option{}, false
}

func hasOption(s Spec, name string) bool {
	_, ok := optionNamed(s, name)
	return ok
}

func optionValue(s Spec, name, def string) string {
	o, ok := optionNamed(s, name)
	if !ok {
		return def
	}
	if !o.Has {
		return "1"
	}
	return o.Value
}

func optionActive(o Option) bool {
	if !o.Has {
		return true
	}
	v := strings.ToLower(strings.TrimSpace(o.Value))
	if v == "" {
		return false
	}
	return v != "0" && v != "false" && v != "no" && v != "off"
}

func boolOption(s Spec, name string) bool {
	o, ok := optionNamed(s, name)
	if !ok {
		return false
	}
	return optionActive(o)
}
