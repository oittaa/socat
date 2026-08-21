package relay

import (
	"io"
)

func writeDump(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func dump(cfg Config, dir string, data []byte) error {
	if cfg.Dump == nil {
		return nil
	}
	const maxDumpOutputBuffer = 256 << 10
	maxEncoded := 4 * len(data)
	if cfg.Hex {
		maxEncoded = 3 * len(data)
	}
	if len(dir)+2+maxEncoded > maxDumpOutputBuffer {
		return dumpLarge(cfg, dir, data)
	}
	out := make([]byte, 0, len(dir)+2+maxEncoded)
	out = append(out, dir...)
	out = append(out, ' ')
	const hexDigits = "0123456789abcdef"
	if cfg.Hex {
		for i, b := range data {
			if i > 0 {
				out = append(out, ' ')
			}
			out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
		}
		out = append(out, '\n')
		return writeDump(cfg.Dump, out)
	}
	// text mode with simple escapes
	for _, b := range data {
		switch {
		case b == '\n':
			out = append(out, '\\', 'n')
		case b == '\r':
			out = append(out, '\\', 'r')
		case b == '\t':
			out = append(out, '\\', 't')
		case b < 32 || b >= 127:
			out = append(out, '\\', 'x', hexDigits[b>>4], hexDigits[b&0x0f])
		default:
			out = append(out, b)
		}
	}
	out = append(out, '\n')
	return writeDump(cfg.Dump, out)
}

// dumpLarge preserves the single-line dump format without allocating up to
// four times an arbitrarily large relay buffer. Normal 8 KiB dumps stay on the
// faster single-write path above.
func dumpLarge(cfg Config, dir string, data []byte) error {
	if err := writeDump(cfg.Dump, []byte(dir+" ")); err != nil {
		return err
	}
	const inputChunk = 64 << 10
	const hexDigits = "0123456789abcdef"
	for start := 0; start < len(data); start += inputChunk {
		end := min(start+inputChunk, len(data))
		chunk := data[start:end]
		out := make([]byte, 0, 4*len(chunk))
		if cfg.Hex {
			for i, b := range chunk {
				if start+i > 0 {
					out = append(out, ' ')
				}
				out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
			}
		} else {
			for _, b := range chunk {
				switch {
				case b == '\n':
					out = append(out, '\\', 'n')
				case b == '\r':
					out = append(out, '\\', 'r')
				case b == '\t':
					out = append(out, '\\', 't')
				case b < 32 || b >= 127:
					out = append(out, '\\', 'x', hexDigits[b>>4], hexDigits[b&0x0f])
				default:
					out = append(out, b)
				}
			}
		}
		if err := writeDump(cfg.Dump, out); err != nil {
			return err
		}
	}
	return writeDump(cfg.Dump, []byte{'\n'})
}
