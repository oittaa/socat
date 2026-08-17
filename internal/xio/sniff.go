package xio

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// expandSniffPath expands classic -r/-R path variables (sysutils.c expandenv).
// Special: $$ pid, $PROGNAME, $TIMESTAMP (%Y%m%dT%H%M%S), $MICROS; else getenv.
// \$ yields a literal $.
func expandSniffPath(src string, progname string, now time.Time, g *Global) (string, error) {
	if progname == "" {
		progname = "socat"
	}
	var b strings.Builder
	b.Grow(len(src) + 32)
	for i := 0; i < len(src); {
		c := src[i]
		if c == '\\' && i+1 < len(src) {
			// Only \$ is special; other escapes keep the next char (classic).
			if src[i+1] == '$' {
				b.WriteByte('$')
				i += 2
				continue
			}
			b.WriteByte(src[i+1])
			i += 2
			continue
		}
		if c != '$' {
			b.WriteByte(c)
			i++
			continue
		}
		// $ at end
		if i+1 >= len(src) {
			b.WriteByte('$')
			i++
			continue
		}
		// $$
		if src[i+1] == '$' {
			b.WriteString(strconv.Itoa(os.Getpid()))
			i += 2
			continue
		}
		// ${name} or $name
		j := i + 1
		brace := false
		if src[j] == '{' {
			brace = true
			j++
		}
		start := j
		for j < len(src) {
			ch := rune(src[j])
			if !unicode.IsLetter(ch) && !unicode.IsDigit(ch) && ch != '_' {
				break
			}
			j++
		}
		if brace {
			if j >= len(src) || src[j] != '}' {
				return "", fmt.Errorf("sniff path: bad ${} in %q", src)
			}
		}
		name := src[start:j]
		if brace {
			j++ // skip }
		}
		if name == "" {
			b.WriteByte('$')
			i++
			continue
		}
		var val string
		switch name {
		case "PROGNAME":
			val = progname
		case "TIMESTAMP":
			val = now.Format("20060102T150405")
		case "MICROS":
			val = fmt.Sprintf("%06d", now.Nanosecond()/1000)
		default:
			if v, ok := sniffEnvValue(g, name); ok {
				val = v
			} else {
				val = os.Getenv(name)
			}
		}
		// Missing env vars expand to empty (classic skips them).
		b.WriteString(val)
		i = j
	}
	return b.String(), nil
}

// openSniffFiles opens -r/-R dump files for this transfer after expanding paths.
// Uses O_APPEND|O_CREAT|O_CLOEXEC like classic xio_opensnifffile.
func openSniffFiles(g *Global) error {
	if g == nil {
		return nil
	}
	// Close previous session files (fork children re-open).
	if g.RawLeft != nil {
		_ = g.RawLeft.Close()
		g.RawLeft = nil
	}
	if g.RawRight != nil {
		_ = g.RawRight.Close()
		g.RawRight = nil
	}
	now := time.Now()
	prog := g.Progname
	if prog == "" {
		prog = "socat"
	}
	if g.RawLeftPath != "" {
		path, err := expandSniffPath(g.RawLeftPath, prog, now, g)
		if err != nil {
			return fmt.Errorf("-r: %w", err)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|oCloexec, 0o664) // #nosec G302 G304 -- -r/-R sniff path comes from the user; 0664 is a readable dump
		if err != nil {
			return fmt.Errorf("-r %q: %w", path, err)
		}
		g.RawLeft = f
	}
	if g.RawRightPath != "" {
		path, err := expandSniffPath(g.RawRightPath, prog, now, g)
		if err != nil {
			return fmt.Errorf("-R: %w", err)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|oCloexec, 0o664) // #nosec G302 G304 -- -r/-R sniff path comes from the user; 0664 is a readable dump
		if err != nil {
			return fmt.Errorf("-R %q: %w", path, err)
		}
		g.RawRight = f
	}
	return nil
}
