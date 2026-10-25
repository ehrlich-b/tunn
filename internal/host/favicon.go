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
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && (r.URL.Path == "/favicon.ico" || r.URL.Path == "/favicon.svg")
}

func serveTunnelFavicon(w http.ResponseWriter, r *http.Request, tunnel *TunnelConnection) bool {
	if tunnel.NoFavicon || tunnel.EndpointProtocol == "tcp" || !faviconRequest(r) {
		return false
	}
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
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body.Bytes())
	}
	return true
}

// Only failed icon responses are replaced. Successful bodies stream untouched,
// and failed backend bodies and headers never enter the generated response.
type faviconResponseWriter struct {
	http.ResponseWriter
	request           *http.Request
	tunnel            *TunnelConnection
	header            http.Header
	started, replaced bool
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
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.started = true
	if status == 404 || status == 410 {
		w.replaced = serveTunnelFavicon(w.ResponseWriter, w.request, w.tunnel)
		if w.replaced {
			return
		}
	}
	for k := range w.ResponseWriter.Header() {
		w.ResponseWriter.Header().Del(k)
	}
	for k, v := range w.header {
		w.ResponseWriter.Header()[k] = append([]string(nil), v...)
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *faviconResponseWriter) Write(b []byte) (int, error) {
	if !w.started {
		w.WriteHeader(200)
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
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
