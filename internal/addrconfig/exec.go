package addrconfig

import "strings"

func decodeProcessCommand(a *Address) {
	switch a.Facts.Kind {
	case AddressKindEXEC:
		a.Process.Argv = splitExecArgs(strings.Join(a.Params, ":"))
	case AddressKindSYSTEM, AddressKindSHELL:
		a.Process.Command = strings.Join(a.Params, ":")
		a.Process.HasCommand = len(a.Params) > 0
	}
}

// splitExecArgs splits an EXEC command line. Unquoted spaces separate
// arguments; tabs and other non-space bytes stay inside an argument.
// ASCII whitespace before the program name is skipped. Double-quoted
// segments keep spaces and may be empty ("" → empty arg); \" inside
// quotes is a literal quote.
func splitExecArgs(s string) []string {
	s = s[skipExecProgramSpace(s):]

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
		if !inDouble && c == ' ' {
			flush()
			continue
		}
		cur.WriteByte(c)
	}
	flush()
	return args
}

// skipExecProgramSpace returns the index after ASCII whitespace that
// precedes the program name. Later tabs are argument text.
func skipExecProgramSpace(s string) int {
	i := 0
	for i < len(s) && isExecProgramSpace(s[i]) {
		i++
	}
	return i
}

func isExecProgramSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}
