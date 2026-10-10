package host

import "encoding/binary"

// Track only framing boundaries, with constant memory. If the byte cutoff falls
// inside a frame, terminating the socket is safer than inserting a close frame
// into its payload. Publishers already validate every forwarded frame.
type webSocketBoundary struct {
	header     [14]byte
	have, need int
	remaining  uint64
}

func (b *webSocketBoundary) atBoundary() bool { return b.have == 0 && b.remaining == 0 }
func (b *webSocketBoundary) consume(data []byte) {
	for len(data) > 0 {
		if b.remaining > 0 {
			n := min(uint64(len(data)), b.remaining)
			b.remaining -= n
			data = data[n:]
			continue
		}
		if b.need == 0 {
			b.need = 2
		}
		n := min(len(data), b.need-b.have)
		copy(b.header[b.have:], data[:n])
		b.have += n
		data = data[n:]
		if b.have < b.need {
			continue
		}
		if b.need == 2 {
			length := b.header[1] & 0x7f
			switch length {
			case 126:
				b.need += 2
			case 127:
				b.need += 8
			}
			if b.header[1]&0x80 != 0 {
				b.need += 4
			}
			if b.have < b.need {
				continue
			}
		}
		b.remaining = uint64(b.header[1] & 0x7f)
		switch b.remaining {
		case 126:
			b.remaining = uint64(binary.BigEndian.Uint16(b.header[2:4]))
		case 127:
			b.remaining = binary.BigEndian.Uint64(b.header[2:10])
		}
		b.have, b.need = 0, 0
	}
}
