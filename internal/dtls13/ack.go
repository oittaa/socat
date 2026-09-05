package dtls13

import (
	"encoding/binary"
	"errors"
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
	if len(data) < 2 || len(data) > maxContent || int(binary.BigEndian.Uint16(data)) != len(data)-2 || (len(data)-2)%16 != 0 {
		return nil, errACK
	}
	records := make([]recordNumber, 0, (len(data)-2)/16)
	for data = data[2:]; len(data) != 0; data = data[16:] {
		records = append(records, recordNumber{binary.BigEndian.Uint64(data[:8]), binary.BigEndian.Uint64(data[8:16])})
	}
	return records, nil
}
