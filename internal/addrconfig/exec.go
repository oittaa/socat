package addrconfig

import "strings"

func decodeProcessCommand(a *Address) {
	switch a.Facts.Kind {
	case AddressKindEXEC:
		a.Process.Argv = splitExecArgs(strings.Join(a.Params, ":"))
	case AddressKindSYSTEM, AddressKindSHELL:
		a.Process.Command = strings.Join(a.Params, ":")
		a.Process.HasCommand = len(a.Params) > 0 && a.Params[0] != ""
	}
}

// splitExecArgs splits an EXEC command line: unquoted runs of spaces
// separate args (no empty args from bare spaces); double-quoted segments
// keep spaces and may be empty ("" → empty arg); \" inside quotes is a
// literal quote (so -c 'echo "$1"' works).
func splitExecArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inDouble := false
	escape := false
	// sawQuote marks a quoted segment so "" becomes an empty argument.
	sawQuote := false

	flush := func() {
		if sawQuote || cur.Len() > 0 {
			args = append(args, cur.String())
		}
		cur.Reset()
		sawQuote = false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			cur.WriteByte(c)
			escape = false
			continue
		}
		if c == '\\' && inDouble {
			escape = true
			continue
		}
		if c == '"' {
			inDouble = !inDouble
			sawQuote = true
			continue // drop delimiter
		}
		if !inDouble && (c == ' ' || c == '\t') {
			flush()
			// collapse consecutive unquoted whitespace
			continue
		}
		cur.WriteByte(c)
	}
	flush()
	return args
}
