package common

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestWebSocketFramesValidateBeforePayload(t *testing.T) {
	for _, test := range []struct {
		name   string
		header []byte
		want   error
	}{
		{"too large", []byte{0x82, 126, 0x10, 0}, ErrWebSocketMessageTooLarge},
		{"overflow length", []byte{0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0}, ErrWebSocketProtocol},
		{"nonminimal16", []byte{0x82, 126, 0, 1}, ErrWebSocketProtocol},
		{"nonminimal64", []byte{0x82, 127, 0, 0, 0, 0, 0, 0, 0, 1}, ErrWebSocketProtocol},
		{"extension", []byte{0xc1, 0}, ErrWebSocketProtocol},
		{"unrequested continuation", []byte{0x80, 0}, ErrWebSocketProtocol},
		{"reserved opcode", []byte{0x83, 0}, ErrWebSocketProtocol},
		{"fragmented control", []byte{0x09, 0}, ErrWebSocketProtocol},
		{"large control", []byte{0x89, 126, 0, 126}, ErrWebSocketProtocol},
		{"close length one", []byte{0x88, 1}, ErrWebSocketProtocol},
		{"wrong mask", []byte{0x81, 0x80}, ErrWebSocketProtocol},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			writer := &WebSocketFrameWriter{Writer: &output}
			err := writer.CopyFrames(bytes.NewReader(test.header), false, 1024)
			if !errors.Is(err, test.want) {
				t.Fatalf("error %v, want %v", err, test.want)
			}
			if output.Len() != 0 {
				t.Fatal("invalid frame header reached target")
			}
		})
	}
}
func TestWebSocketFragmentedLimitWithControlFrames(t *testing.T) {
	input := []byte{0x02, 3, 'a', 'b', 'c', 0x89, 1, 'p', 0x80, 3, 'd', 'e', 'f'}
	var output bytes.Buffer
	err := (&WebSocketFrameWriter{Writer: &output}).CopyFrames(bytes.NewReader(input), false, 5)
	if !errors.Is(err, ErrWebSocketMessageTooLarge) {
		t.Fatalf("error %v", err)
	}
	if !bytes.Equal(output.Bytes(), input[:8]) {
		t.Fatalf("forwarded bytes %x", output.Bytes())
	}
}
func TestWebSocketFrameBoundedBackpressure(t *testing.T) {
	// The destination blocks at its first write. The copier must consume only
	// a frame header, not buffer a message while its consumer is stalled.
	header := []byte{0x82, 127}
	header = binary.BigEndian.AppendUint64(header, 1<<20)
	source := bytes.NewReader(append(header, make([]byte, 1<<20)...))
	arrived, resume := make(chan struct{}), make(chan struct{})
	output := &blockedWebSocketWriter{arrived: arrived, resume: resume}
	result := make(chan error, 1)
	go func() { result <- (&WebSocketFrameWriter{Writer: output}).CopyFrames(source, false, 2<<20) }()
	<-arrived
	if source.Len() != 1<<20 {
		t.Errorf("stalled consumer buffered %d payload bytes", (1<<20)-source.Len())
	}
	close(resume)
	if err := <-result; err != io.EOF {
		t.Fatalf("copy error %v", err)
	}
}

type blockedWebSocketWriter struct {
	arrived, resume chan struct{}
	first           bool
}

func (w *blockedWebSocketWriter) Write(p []byte) (int, error) {
	if !w.first {
		w.first = true
		close(w.arrived)
		<-w.resume
	}
	return len(p), nil
}
func TestWebSocketFramePreservesMaskedControls(t *testing.T) {
	// A masked close with code 1000.
	frame := []byte{0x88, 0x82, 1, 2, 3, 4, 3 ^ 1, 232 ^ 2}
	var output bytes.Buffer
	if err := (&WebSocketFrameWriter{Writer: &output}).CopyFrames(bytes.NewReader(frame), true, 1024); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), frame) {
		t.Fatal("masked close changed")
	}
}
