package dtls13

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

var errACK = errors.New("dtls: malformed acknowledgement")

func compareRecordNumber(a, b recordNumber) int {
	if a.epoch < b.epoch || a.epoch == b.epoch && a.sequence < b.sequence {
		return -1
	}
	if a == b {
		return 0
	}
	return 1
}

func encodeACK(records []recordNumber) ([]byte, error) {
	if len(records) > (maxContent-2)/16 {
		return nil, errACK
	}
	records = slices.Clone(records)
	slices.SortFunc(records, compareRecordNumber)
	records = slices.Compact(records)
	n := 16 * len(records)
	if n > maxContent-2 {
		return nil, errACK
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(n))
	for _, r := range records {
		b = binary.BigEndian.AppendUint64(b, r.epoch)
		b = binary.BigEndian.AppendUint64(b, r.sequence)
	}
	return b, nil
}

func parseACK(data []byte) ([]recordNumber, error) {
	if len(data) < 2 || len(data) > maxContent {
		return nil, errACK
	}
	declared := int(binary.BigEndian.Uint16(data))
	body := data[2:]
	size := len(body)
	if declared < size {
		size = declared
	}
	// A truncated list still yields complete record numbers. OpenSSL 4.1 may
	// advertise more ACK entries than fit in the current MTU.
	size -= size % 16
	if declared == 0 && len(body) == 0 {
		return nil, nil
	}
	if size == 0 {
		return nil, fmt.Errorf("%w (len %d declared %d)", errACK, len(data), declared)
	}
	records := make([]recordNumber, 0, size/16)
	for i := 0; i < size; i += 16 {
		records = append(records, recordNumber{binary.BigEndian.Uint64(body[i : i+8]), binary.BigEndian.Uint64(body[i+8 : i+16])})
	}
	return records, nil
}
