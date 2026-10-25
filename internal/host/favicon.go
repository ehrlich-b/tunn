package host

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strconv"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
)

// faviconPixels contains only public hostname-derived data. A mirrored 5x5
// pattern stays recognizable at tab size; the hash also selects its hue.
func faviconPixels(host string) *image.RGBA {
	hash := sha256.Sum256([]byte(strings.ToLower(requestHostname(host))))
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	hue := int(hash[0]) * 6
	sector, x := hue/256, hue%256
	x = x * 3 / 4
	var ink color.RGBA
	switch sector {
	case 0:
		ink = color.RGBA{210, uint8(x), 30, 255}
	case 1:
		ink = color.RGBA{210 - uint8(x), 210, 30, 255}
	case 2:
		ink = color.RGBA{30, 210, uint8(x) + 30, 255}
	case 3:
		ink = color.RGBA{30, 210 - uint8(x), 210, 255}
	case 4:
		ink = color.RGBA{uint8(x) + 30, 30, 210, 255}
	default:
		ink = color.RGBA{210, 30, 210 - uint8(x), 255}
	}
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			c := color.RGBA{245, 245, 245, 255}
			if x >= 3 && x < 28 && y >= 3 && y < 28 {
				col, row := (x-3)/5, (y-3)/5
				if col > 2 {
					col = 4 - col
				}
				if row == 2 && col == 2 || hash[1+(row*3+col)/8]&(1<<uint((row*3+col)%8)) != 0 {
					c = ink
				}
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img
}

func faviconRequest(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && !common.IsWebSocketUpgrade(r.Header) && (r.URL.Path == "/favicon.ico" || r.URL.Path == "/favicon.svg")
}

func serveTunnelFavicon(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection) bool {
	if tunnel.NoFavicon || tunnel.EndpointProtocol == "tcp" || !faviconRequest(r) {
		return false
	}
	_ = writeTunnelFavicon(w, r)
	return true
}

func writeTunnelFavicon(w http.ResponseWriter, r *http.Request) error {
	img := faviconPixels(r.Host)
	var body bytes.Buffer
	contentType := "image/png"
	if r.URL.Path == "/favicon.svg" {
		contentType = "image/svg+xml"
		body.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">`)
		body.WriteString(`<path fill="#f5f5f5" d="M0 0h32v32H0z"/>`)
		for y := 3; y < 28; y += 5 {
			for x := 3; x < 28; x += 5 {
				c := img.RGBAAt(x, y)
				if c.R != 245 || c.G != 245 || c.B != 245 {
					fmt.Fprintf(&body, `<path fill="#%02x%02x%02x" d="M%d %dh5v5h-5z"/>`, c.R, c.G, c.B, x, y)
				}
			}
		}
		body.WriteString(`</svg>`)
	} else {
		_ = png.Encode(&body, img)
	}
	// Reserve the generated body before committing a success. Backend error
	// bodies are discarded outside the meter and consume no response allowance.
	meter, metered := w.(*meterResponseWriter)
	if metered && meter.bodyMeter && r.Method != http.MethodHead {
		if _, err := meter.meter.charge(r.Context(), false, body.Len()); err != nil {
			return err
		}
		meter.bodyMeter = false
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		n, err := w.Write(body.Bytes())
		if metered {
			recordMeteredWrite(r, n)
		}
		if err != nil {
			return &responseStartedError{err: truncatedHTTPResponse(err)}
		}
	}
	return nil
}

// Only failed icon responses are replaced. Successful bodies stream untouched,
// and failed backend bodies and headers never enter the generated response.
type faviconResponseWriter struct {
	http.ResponseWriter
	request           *http.Request
	tunnel            *TunnelConnection
	header            http.Header
	started, replaced bool
	err               error
}

func (w *faviconResponseWriter) Header() http.Header {
	if w.started && !w.replaced {
		return w.ResponseWriter.Header()
	}
	return w.header
}
func (w *faviconResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *faviconResponseWriter) WriteHeader(status int) {
	if w.started {
		return
	}
	if status < 200 {
		// Informational headers belong to this response too, but must not
		// become backend headers on a later generated fallback.
		original := w.ResponseWriter.Header().Clone()
		w.copyHeaders(w.header)
		w.ResponseWriter.WriteHeader(status)
		w.copyHeaders(original)
		return
	}
	w.started = true
	if w.fallback(status) {
		w.replaced = true
		w.err = writeTunnelFavicon(w.ResponseWriter, w.request)
		return
	}
	w.copyHeaders(w.header)
	w.ResponseWriter.WriteHeader(status)
}

func (w *faviconResponseWriter) fallback(status int) bool {
	return (status == http.StatusNotFound || status == http.StatusGone) && !w.tunnel.NoFavicon && w.tunnel.EndpointProtocol != "tcp" && faviconRequest(w.request)
}

func (w *faviconResponseWriter) copyHeaders(source http.Header) {
	target := w.ResponseWriter.Header()
	for k := range target {
		delete(target, k)
	}
	for k, v := range source {
		target[k] = append([]string(nil), v...)
	}
}
func (w *faviconResponseWriter) Write(b []byte) (int, error) {
	if !w.started {
		w.WriteHeader(200)
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.replaced {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}
func (w *faviconResponseWriter) Flush() {
	if !w.started {
		w.WriteHeader(200)
	}
	if w.err == nil {
		_ = http.NewResponseController(w.ResponseWriter).Flush()
	}
}
