package relay

import (
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	// maxDumpOutputBuffer is the largest formatted record built in one buffer.
	// Larger records are written in bounded chunks.
	maxDumpOutputBuffer = 256 << 10
	dumpInputChunk      = 64 << 10
	dumpHexWidth        = 16
)

const hexDigits = "0123456789abcdef"

// dumpMu keeps one dump record intact while the two transfer directions run.
var dumpMu sync.Mutex

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

func dump(cfg Config, dir string, offset uint64, data []byte) error {
	if cfg.Dump == nil || len(data) == 0 {
		return nil
	}
	dumpMu.Lock()
	defer dumpMu.Unlock()
	header := appendDumpHeader(nil, dir, len(data), offset)
	limit := dumpBodyLimit(cfg, len(data))
	if limit > maxDumpOutputBuffer || len(header) > maxDumpOutputBuffer-limit {
		return dumpLarge(cfg, header, data)
	}
	out := make([]byte, 0, len(header)+limit)
	out = append(out, header...)
	out = appendDumpBody(out, cfg, data)
	return writeDump(cfg.Dump, out)
}

func appendDumpHeader(out []byte, dir string, n int, offset uint64) []byte {
	ts := time.Now().Format("2006/01/02 15:04:05.000000")
	end := offset + uint64(n) - 1 // #nosec G115 -- n is a slice length, so it is non-negative
	return fmt.Appendf(out, "%s %s  length=%d from=%d to=%d\n", dir, ts, n, offset, end)
}

func dumpBodyLimit(cfg Config, n int) int {
	const maxInt = int(^uint(0) >> 1)
	per, extra := 2, 0
	switch {
	case cfg.Verbose && cfg.Hex:
		// One padded row per byte when every byte is a newline, plus "--\n".
		per, extra = 52, 3
	case cfg.Hex:
		per, extra = 3, 1
	}
	if n > (maxInt-extra)/per {
		return maxInt
	}
	return per*n + extra
}

func appendDumpBody(out []byte, cfg Config, data []byte) []byte {
	switch {
	case cfg.Verbose && cfg.Hex:
		return appendCombinedDump(out, data)
	case cfg.Hex:
		return appendHexDump(out, data)
	default:
		return appendTextDump(out, data)
	}
}

func appendTextDump(out []byte, data []byte) []byte {
	for _, b := range data {
		out = appendTextByte(out, b)
	}
	return out
}

func appendTextByte(out []byte, b byte) []byte {
	switch b {
	case '\a':
		return append(out, '\\', 'a')
	case '\b':
		return append(out, '\\', 'b')
	case '\t':
		return append(out, '\t')
	case '\n':
		return append(out, '\n')
	case '\v':
		return append(out, '\\', 'v')
	case '\f':
		return append(out, '\\', 'f')
	case '\r':
		return append(out, '\\', 'r')
	case '\\':
		return append(out, '\\', '\\')
	default:
		if b < 0x20 || b >= 0x7f {
			return append(out, '.')
		}
		return append(out, b)
	}
}

func appendHexDump(out []byte, data []byte) []byte {
	for _, b := range data {
		out = appendHexByte(out, b)
	}
	return append(out, '\n')
}

func appendHexByte(out []byte, b byte) []byte {
	return append(out, ' ', hexDigits[b>>4], hexDigits[b&0x0f])
}

func appendCombinedDump(out []byte, data []byte) []byte {
	for len(data) > 0 {
		out, data = appendCombinedRow(out, data)
	}
	return append(out, '-', '-', '\n')
}

func appendCombinedRow(out, data []byte) ([]byte, []byte) {
	n := dumpHexWidth
	if n > len(data) {
		n = len(data)
	}
	row := n
	for i := 0; i < n; i++ {
		if data[i] == '\n' {
			row = i + 1
			break
		}
	}
	for i := 0; i < row; i++ {
		out = appendHexByte(out, data[i])
	}
	for i := row; i < dumpHexWidth; i++ {
		out = append(out, ' ', ' ', ' ')
	}
	out = append(out, ' ', ' ')
	for i := 0; i < row; i++ {
		b := data[i]
		if b == '\n' {
			out = append(out, '.')
			break
		}
		if b < 0x20 || b >= 0x7f {
			out = append(out, '.')
		} else {
			out = append(out, b)
		}
	}
	return append(out, '\n'), data[row:]
}

// dumpLarge writes one record in bounded chunks. Each chunk is allocated
// separately so a large relay buffer is not formatted into one output buffer.
func dumpLarge(cfg Config, header, data []byte) error {
	if err := writeDump(cfg.Dump, header); err != nil {
		return err
	}
	switch {
	case cfg.Verbose && cfg.Hex:
		return writeCombinedChunks(cfg.Dump, data)
	case cfg.Hex:
		return writeHexChunks(cfg.Dump, data)
	default:
		return writeTextChunks(cfg.Dump, data)
	}
}

func writeCombinedChunks(w io.Writer, data []byte) error {
	out := make([]byte, 0, dumpInputChunk)
	for len(data) > 0 {
		out, data = appendCombinedRow(out, data)
		if len(out) >= dumpInputChunk {
			if err := writeDump(w, out); err != nil {
				return err
			}
			out = make([]byte, 0, dumpInputChunk)
		}
	}
	out = append(out, '-', '-', '\n')
	return writeDump(w, out)
}

func writeHexChunks(w io.Writer, data []byte) error {
	for start := 0; start < len(data); start += dumpInputChunk {
		end := min(start+dumpInputChunk, len(data))
		chunk := data[start:end]
		out := make([]byte, 0, 3*len(chunk))
		for _, b := range chunk {
			out = appendHexByte(out, b)
		}
		if err := writeDump(w, out); err != nil {
			return err
		}
	}
	return writeDump(w, []byte{'\n'})
}

func writeTextChunks(w io.Writer, data []byte) error {
	for start := 0; start < len(data); start += dumpInputChunk {
		end := min(start+dumpInputChunk, len(data))
		chunk := data[start:end]
		out := make([]byte, 0, 2*len(chunk))
		for _, b := range chunk {
			out = appendTextByte(out, b)
		}
		if err := writeDump(w, out); err != nil {
			return err
		}
	}
	return nil
}
