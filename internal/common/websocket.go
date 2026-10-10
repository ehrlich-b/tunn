package common

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebSocketOptions applies to both directions of an upgraded HTTP connection.
// A nil options pointer selects defaults; explicit zero durations disable timers.
type WebSocketOptions struct {
	IdleTimeout       time.Duration
	KeepaliveInterval time.Duration
	MaxMessageSize    int64
}

func DefaultWebSocketOptions() WebSocketOptions {
	return WebSocketOptions{IdleTimeout: 5 * time.Minute, KeepaliveInterval: 30 * time.Second, MaxMessageSize: 8 << 20}
}

func (o WebSocketOptions) Validate() error {
	if o.IdleTimeout < 0 || o.KeepaliveInterval < 0 {
		return fmt.Errorf("WebSocket durations cannot be negative")
	}
	if o.MaxMessageSize < 1 || o.MaxMessageSize > 100<<20 {
		return fmt.Errorf("WebSocket message limit must be between 1 and 104857600 bytes")
	}
	return nil
}

func HeaderHasToken(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func IsWebSocketUpgrade(h http.Header) bool {
	return HeaderHasToken(h.Get("Upgrade"), "websocket")
}

func ValidWebSocketRequest(r *http.Request) bool {
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	return r.Method == http.MethodGet && r.ProtoMajor == 1 && r.ContentLength <= 0 &&
		IsWebSocketUpgrade(r.Header) && HeaderHasToken(r.Header.Get("Connection"), "upgrade") &&
		r.Header.Get("Sec-WebSocket-Version") == "13" && err == nil && len(key) == 16
}

func WebSocketAccept(key string) string {
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func ValidWebSocketResponse(h http.Header, key string) bool {
	return IsWebSocketUpgrade(h) && HeaderHasToken(h.Get("Connection"), "upgrade") &&
		h.Get("Sec-WebSocket-Accept") == WebSocketAccept(key) && h.Get("Sec-WebSocket-Extensions") == ""
}

var ErrWebSocketMessageTooLarge = errors.New("WebSocket message exceeds configured limit")
var ErrWebSocketProtocol = errors.New("invalid WebSocket frame")

// WebSocketFrameWriter preserves wire frames, including masks, fragmentation,
// ping/pong and close payloads. Extensions are deliberately not negotiated, so
// the size limit is the actual message size, including all continuation frames.
// Memory stays bounded to one transport chunk, regardless of message size.
type WebSocketFrameWriter struct {
	Writer io.Writer
	mu     sync.Mutex
	closed bool
}

func (w *WebSocketFrameWriter) CopyFrames(source io.Reader, masked bool, maxMessageSize int64) error {
	buffer := make([]byte, StreamChunkSize)
	var fragmented bool
	var messageSize uint64
	for {
		var header [14]byte
		if _, err := io.ReadFull(source, header[:2]); err != nil {
			return err
		}
		fin, opcode := header[0]&0x80 != 0, header[0]&0x0f
		if header[0]&0x70 != 0 || (header[1]&0x80 != 0) != masked {
			return ErrWebSocketProtocol
		}
		length, headerLen := uint64(header[1]&0x7f), 2
		switch length {
		case 126:
			if _, err := io.ReadFull(source, header[2:4]); err != nil {
				return err
			}
			length, headerLen = uint64(binary.BigEndian.Uint16(header[2:4])), 4
			if length < 126 {
				return ErrWebSocketProtocol
			}
		case 127:
			if _, err := io.ReadFull(source, header[2:10]); err != nil {
				return err
			}
			length, headerLen = binary.BigEndian.Uint64(header[2:10]), 10
			if length < 65536 || length>>63 != 0 {
				return ErrWebSocketProtocol
			}
		}
		control := opcode >= 8
		switch opcode {
		case 0:
			if !fragmented {
				return ErrWebSocketProtocol
			}
		case 1, 2:
			if fragmented {
				return ErrWebSocketProtocol
			}
			messageSize = 0
		case 8, 9, 10:
			if !fin || length > 125 || (opcode == 8 && length == 1) {
				return ErrWebSocketProtocol
			}
		default:
			return ErrWebSocketProtocol
		}
		if !control {
			if length > uint64(maxMessageSize) || messageSize > uint64(maxMessageSize)-length {
				return ErrWebSocketMessageTooLarge
			}
			messageSize += length
			fragmented = !fin
		}
		if masked {
			if _, err := io.ReadFull(source, header[headerLen:headerLen+4]); err != nil {
				return err
			}
			headerLen += 4
		}
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			// Consume this frame before stopping the reader. A duplex peer may
			// be writing its close reply on an unbuffered/backpressured socket.
			_, _ = io.CopyBuffer(io.Discard, io.LimitReader(source, int64(length)), buffer)
			return io.EOF
		}
		_, err := w.Writer.Write(header[:headerLen])
		if err == nil {
			var n int64
			n, err = io.CopyBuffer(w.Writer, io.LimitReader(source, int64(length)), buffer)
			if err == nil && n != int64(length) {
				err = io.ErrUnexpectedEOF
			}
		}
		if opcode == 8 {
			w.closed = true
		}
		w.mu.Unlock()
		if err != nil || opcode == 8 {
			return err
		}
	}
}

// TryControl skips a busy frame instead of blocking the timeout/keepalive loop
// on a peer that has stopped halfway through a frame. Frames never interleave.
func (w *WebSocketFrameWriter) TryControl(opcode byte, payload []byte, masked bool) error {
	if !w.mu.TryLock() {
		return nil
	}
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	if len(payload) > 125 {
		return ErrWebSocketProtocol
	}
	frame := []byte{0x80 | opcode, byte(len(payload))}
	if masked {
		frame[1] |= 0x80
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		frame = append(frame, mask[:]...)
		for i, value := range payload {
			frame = append(frame, value^mask[i%4])
		}
	} else {
		frame = append(frame, payload...)
	}
	_, err := w.Writer.Write(frame)
	if opcode == 8 {
		w.closed = true
	}
	return err
}
