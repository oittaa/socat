package parse

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
