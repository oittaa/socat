package parse

import "github.com/oittaa/socat/internal/optionmeta"

func init() {
	registerOptionAliases(getOnlyIPv4Aliases())
}

func getOnlyIPv4Aliases() map[string]string {
	aliases := make(map[string]string)
	for _, opt := range optionmeta.GetOnlyIPv4() {
		for _, alias := range opt.Aliases {
			if prev, ok := aliases[alias]; ok {
				panic("duplicate option alias " + alias + ": " + prev + " vs " + opt.Canonical)
			}
			aliases[alias] = opt.Canonical
		}
	}
	return aliases
}
