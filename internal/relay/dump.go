package relay

import (
	"fmt"
	"io"
	"time"
)

const (
	// maxDumpOutputBuffer is the largest formatted record built in one buffer.
	// Larger records are written in bounded chunks.
	maxDumpOutputBuffer = 256 << 10
	dumpInputChunk      = 64 << 10
)

const hexDigits = "0123456789abcdef"

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
	if cfg.Hex {
		per, extra = 3, 1
	}
	if n > (maxInt-extra)/per {
		return maxInt
	}
	return per*n + extra
}

func appendDumpBody(out []byte, cfg Config, data []byte) []byte {
	if cfg.Hex {
		return appendHexDump(out, data)
	}
	return appendTextDump(out, data)
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

// dumpLarge writes one record in bounded chunks. Each chunk is allocated
// separately so a large relay buffer is not formatted into one output buffer.
func dumpLarge(cfg Config, header, data []byte) error {
	if err := writeDump(cfg.Dump, header); err != nil {
		return err
	}
	if cfg.Hex {
		return writeHexChunks(cfg.Dump, data)
	}
	return writeTextChunks(cfg.Dump, data)
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
