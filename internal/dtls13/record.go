package dtls13

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
)

const (
	contentAlert     = byte(21)
	contentHandshake = byte(22)
	contentData      = byte(23)
	contentACK       = byte(26)
	contentRRC       = byte(27)

	// MaxApplicationData is the largest supported application record payload.
	MaxApplicationData = 1 << 14
	maxContent         = MaxApplicationData
	maxCiphertext      = maxContent + 256
	plainHeader        = 13
)

var (
	// ErrDatagramTooLarge rejects an application write before it is sent.
	ErrDatagramTooLarge = errors.New("dtls: record too large")
	errRecord           = errors.New("dtls: invalid record")
	errRecordOverflow   = ErrDatagramTooLarge
	errSequence         = errors.New("dtls: record sequence exhausted")
	errReplay           = errors.New("dtls: replayed record")
)

type recordNumber struct {
	epoch    uint64
	sequence uint64
}

// record aliases one datagram. Decryption never modifies the datagram.
type record struct {
	header    []byte
	body      []byte
	cid       []byte
	number    recordNumber
	typ       byte
	encrypted bool
	seqOffset int
	seqLen    int
}

func parseRecord(datagram []byte, cidLen int) (record, []byte, error) {
	if len(datagram) == 0 || cidLen < 0 || cidLen > 255 {
		return record{}, nil, errRecord
	}
	first := datagram[0]
	r := record{typ: first}
	if first&0xe0 == 0x20 {
		r.encrypted = true
		r.number.epoch = uint64(first & 3)
		r.seqOffset = 1
		if first&0x10 != 0 {
			if cidLen == 0 || len(datagram) < 1+cidLen {
				return record{}, nil, errRecord
			}
			r.cid = datagram[1 : 1+cidLen]
			r.seqOffset += cidLen
		}
		r.seqLen = 1
		if first&0x08 != 0 {
			r.seqLen = 2
		}
		headerLen := r.seqOffset + r.seqLen
		if first&0x04 != 0 {
			headerLen += 2
		}
		if len(datagram) < headerLen {
			return record{}, nil, errRecord
		}
		bodyLen := len(datagram) - headerLen
		if first&0x04 != 0 {
			bodyLen = int(binary.BigEndian.Uint16(datagram[headerLen-2 : headerLen]))
		}
		if bodyLen < 16 || bodyLen > len(datagram)-headerLen {
			return record{}, nil, errRecord
		}
		if bodyLen > maxCiphertext {
			return record{}, nil, errRecordOverflow
		}
		r.header = datagram[:headerLen]
		r.body = datagram[headerLen : headerLen+bodyLen]
		return r, datagram[headerLen+bodyLen:], nil
	}
	if first != contentAlert && first != contentHandshake && first != contentACK {
		return record{}, nil, errRecord
	}
	if len(datagram) < plainHeader {
		return record{}, nil, errRecord
	}
	r.number.epoch = uint64(binary.BigEndian.Uint16(datagram[3:5]))
	if r.number.epoch != 0 {
		return record{}, nil, errRecord
	}
	for _, b := range datagram[5:11] {
		r.number.sequence = r.number.sequence<<8 | uint64(b)
	}
	length := int(binary.BigEndian.Uint16(datagram[11:13]))
	if length > len(datagram)-plainHeader {
		return record{}, nil, errRecord
	}
	if length > maxContent {
		return record{}, nil, errRecordOverflow
	}
	r.header = datagram[:plainHeader]
	r.body = datagram[plainHeader : plainHeader+length]
	return r, datagram[plainHeader+length:], nil
}

func encodePlainRecord(typ byte, sequence uint64, content []byte) ([]byte, error) {
	if sequence >= 1<<48 {
		return nil, errSequence
	}
	if typ != contentHandshake && typ != contentAlert && typ != contentACK {
		return nil, errRecord
	}
	contentLen := len(content)
	if contentLen > maxContent {
		return nil, errRecordOverflow
	}
	encoded := make([]byte, plainHeader, plainHeader+len(content))
	encoded[0], encoded[1], encoded[2] = typ, 0xfe, 0xfd
	for i := 10; i >= 5; i-- {
		encoded[i] = byte(sequence & 0xff)
		sequence >>= 8
	}
	binary.BigEndian.PutUint16(encoded[11:13], uint16(contentLen))
	return append(encoded, content...), nil
}

func (k *trafficKeys) encodeRecord(number recordNumber, cid []byte, typ byte, content []byte, padding int) ([]byte, error) {
	if number.epoch < 2 || len(cid) > 255 || !validContentType(typ) {
		return nil, errRecord
	}
	if len(content) > maxContent || padding < 0 || padding > maxContent-len(content) {
		return nil, errRecordOverflow
	}
	first := byte(0x2c) | byte(number.epoch&3)
	if len(cid) != 0 {
		first |= 0x10
	}
	seqOffset := 1 + len(cid)
	headerLen := seqOffset + 4
	innerLen := len(content) + 1 + padding
	protectedLen := innerLen + k.aead.Overhead()
	if protectedLen < 0 || protectedLen > maxCiphertext {
		return nil, errRecordOverflow
	}
	packet := make([]byte, headerLen+protectedLen)
	packet[0] = first
	copy(packet[1:seqOffset], cid)
	binary.BigEndian.PutUint16(packet[seqOffset:], uint16(number.sequence&0xffff))
	binary.BigEndian.PutUint16(packet[seqOffset+2:], uint16(protectedLen))
	copy(packet[headerLen:], content)
	packet[headerLen+len(content)] = typ
	header := packet[:headerLen]
	inner := packet[headerLen : headerLen+innerLen]
	k.seal(inner[:0], header, number.sequence, inner)
	mask, err := k.mask(packet[headerLen:])
	if err != nil {
		return nil, err
	}
	packet[seqOffset] ^= mask[0]
	packet[seqOffset+1] ^= mask[1]
	return packet, nil
}

func validContentType(typ byte) bool {
	return typ == contentAlert || typ == contentHandshake || typ == contentData || typ == contentACK || typ == contentRRC
}

// The datagram dispatcher enforces CID presence for the whole datagram.
// Individual records may omit it. Replay state changes after authentication.
func (k *trafficKeys) decodeRecord(r record, epoch uint64, cid []byte, window *replayWindow) (recordNumber, byte, []byte, error) {
	if !r.encrypted || r.number.epoch != epoch&3 || len(r.cid) != 0 && !bytes.Equal(cid, r.cid) {
		return recordNumber{}, 0, nil, errAuthentication
	}
	mask, err := k.mask(r.body)
	if err != nil {
		return recordNumber{}, 0, nil, err
	}
	header := bytes.Clone(r.header)
	var truncated uint64
	for i := range r.seqLen {
		header[r.seqOffset+i] ^= mask[i]
		truncated = truncated<<8 | uint64(header[r.seqOffset+i])
	}
	sequence := reconstructSequence(truncated, r.seqLen, window.next())
	inner, err := k.open(header, sequence, r.body)
	if err != nil {
		return recordNumber{}, 0, nil, err
	}
	if len(inner) > maxContent+1 {
		return recordNumber{}, 0, nil, errRecordOverflow
	}
	end := len(inner) - 1
	for end >= 0 && inner[end] == 0 {
		end--
	}
	if end < 0 || !validContentType(inner[end]) {
		return recordNumber{}, 0, nil, errRecord
	}
	if !window.accept(sequence) {
		return recordNumber{}, 0, nil, errReplay
	}
	return recordNumber{epoch, sequence}, inner[end], inner[:end], nil
}

func reconstructSequence(truncated uint64, size int, expected uint64) uint64 {
	window := uint64(1) << (8 * size)
	half := window / 2
	candidate := expected & ^(window-1) | truncated
	if candidate <= expected && expected-candidate >= half && candidate <= math.MaxUint64-window {
		return candidate + window
	}
	if candidate > expected && candidate-expected > half && candidate >= window {
		return candidate - window
	}
	return candidate
}

// A 64-record window satisfies RFC 9147's recommended minimum.
type replayWindow struct {
	highest uint64
	bits    uint64
}

func (w *replayWindow) next() uint64 {
	if w.bits == 0 {
		return 0
	}
	if w.highest == math.MaxUint64 {
		return math.MaxUint64
	}
	return w.highest + 1
}

func (w *replayWindow) accept(sequence uint64) bool {
	if w.bits == 0 {
		w.highest, w.bits = sequence, 1
		return true
	}
	if sequence > w.highest {
		w.bits = w.bits<<(sequence-w.highest) | 1
		w.highest = sequence
		return true
	}
	distance := w.highest - sequence
	if distance >= 64 || w.bits&(uint64(1)<<distance) != 0 {
		return false
	}
	w.bits |= uint64(1) << distance
	return true
}
