package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	inspectBodyLimit  = 64 * 1024
	inspectEventLimit = 50
)

// InspectionEvent is a local, short-lived delivery record. Bodies and headers
// can contain secrets; they never leave the publishing process for inspection.
type InspectionEvent struct {
	ID            uint64            `json:"id"`
	At            time.Time         `json:"at"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Headers       map[string]string `json:"headers"`
	Body          []byte            `json:"body"` // JSON encodes this as base64.
	RequestBytes  int64             `json:"request_bytes"`
	ResponseBytes int64             `json:"response_bytes"`
	Status        int               `json:"status"`
	DurationMS    int64             `json:"duration_ms"`
	Error         string            `json:"error,omitempty"`
	Truncated     bool              `json:"truncated"`
	Replayable    bool              `json:"replayable"`
	ReplayOf      uint64            `json:"replay_of,omitempty"`
}

// Inspector keeps a bounded request history on the publisher's machine.
// A separate ingress audit will account for requests denied before forwarding.
type Inspector struct {
	mu     sync.RWMutex
	events []InspectionEvent
	nextID uint64
	target *ServeClient
	host   string
	token  string
}

func NewInspector(target *ServeClient) *Inspector {
	return &Inspector{target: target}
}

// StartInspector opens the viewer on a random loopback port for this process.
func (i *Inspector) StartInspector(ctx context.Context) (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		_ = listener.Close()
		return "", err
	}
	i.host = listener.Addr().String()
	i.token = hex.EncodeToString(secret)
	server := &http.Server{Handler: i, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() { _ = server.Serve(listener) }()
	// URL fragments are not sent to HTTP servers or referrers. The viewer uses
	// the fragment as a session secret for every request to the local API.
	return "http://" + i.host + "/#" + i.token, nil
}

func (i *Inspector) begin(method, path string, headers map[string]string) *inspectionCapture {
	copyHeaders := make(map[string]string, len(headers))
	for key, value := range headers {
		copyHeaders[key] = value
	}
	return &inspectionCapture{inspector: i, event: InspectionEvent{
		At: time.Now(), Method: method, Path: path, Headers: copyHeaders,
	}}
}

type inspectionCapture struct {
	mu        sync.Mutex
	inspector *Inspector
	event     InspectionEvent
	eof       bool
	finished  bool
}

func (c *inspectionCapture) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		return len(data), nil
	}
	c.event.RequestBytes += int64(len(data))
	space := inspectBodyLimit - len(c.event.Body)
	if space > 0 {
		c.event.Body = append(c.event.Body, data[:min(space, len(data))]...)
	}
	c.event.Truncated = c.event.RequestBytes > inspectBodyLimit
	return len(data), nil
}

func (c *inspectionCapture) complete() {
	c.mu.Lock()
	if !c.finished {
		c.eof = true
	}
	c.mu.Unlock()
}

func (c *inspectionCapture) finish(status int, responseBytes int64, failure string) {
	c.mu.Lock()
	c.finished = true
	event := c.event
	event.Body = append([]byte(nil), c.event.Body...)
	event.Status = status
	event.ResponseBytes = responseBytes
	event.DurationMS = time.Since(event.At).Milliseconds()
	event.Error = failure
	event.Replayable = c.eof && !event.Truncated
	c.mu.Unlock()
	c.inspector.add(event)
}

type inspectionReader struct {
	reader  io.Reader
	capture *inspectionCapture
}

func (r *inspectionReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		_, _ = r.capture.Write(p[:n])
	}
	if err == io.EOF {
		r.capture.complete()
	}
	return n, err
}

func (i *Inspector) add(event InspectionEvent) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.nextID++
	event.ID = i.nextID
	if len(i.events) == inspectEventLimit {
		copy(i.events, i.events[1:])
		i.events[len(i.events)-1] = event
	} else {
		i.events = append(i.events, event)
	}
}

func (i *Inspector) list() []InspectionEvent {
	i.mu.RLock()
	defer i.mu.RUnlock()
	events := make([]InspectionEvent, len(i.events))
	copy(events, i.events)
	return events
}

func (i *Inspector) replay(ctx context.Context, id uint64) (InspectionEvent, error) {
	i.mu.RLock()
	var original InspectionEvent
	found := false
	for _, event := range i.events {
		if event.ID == id {
			original, found = event, true
			break
		}
	}
	i.mu.RUnlock()
	if !found {
		return InspectionEvent{}, fmt.Errorf("delivery not found")
	}
	if !original.Replayable {
		return InspectionEvent{}, fmt.Errorf("delivery body is incomplete or truncated")
	}

	request, err := http.NewRequestWithContext(ctx, original.Method, i.target.targetURL(original.Path), bytes.NewReader(original.Body))
	if err != nil {
		return InspectionEvent{}, errors.New("failed to construct replay request")
	}
	for key, value := range original.Headers {
		request.Header.Set(key, value)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: i.target.SkipLocalTLSVerify}, ForceAttemptHTTP2: true}
	if i.target.TargetNetwork == "unix" {
		address := i.target.DialAddress
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", address)
		}
	}
	defer transport.CloseIdleConnections()
	timeout := i.target.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	replayed := original
	replayed.ID = 0
	replayed.At = time.Now()
	replayed.ReplayOf = id
	replayed.ResponseBytes = 0
	replayed.Status = 0
	replayed.Error = ""
	response, err := client.Do(request)
	if err != nil {
		replayed.Error = "failed to reach local target"
	} else {
		replayed.Status = response.StatusCode
		replayed.ResponseBytes, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024*1024))
		_ = response.Body.Close()
	}
	replayed.DurationMS = time.Since(replayed.At).Milliseconds()
	i.add(replayed)
	if err != nil {
		return replayed, errors.New("failed to reach local target")
	}
	return replayed, nil
}

func (i *Inspector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != i.host {
		http.Error(w, "invalid host", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-inspector'; style-src 'unsafe-inline'; connect-src 'self'")
		_, _ = io.WriteString(w, inspectorHTML)
	case r.Method == http.MethodGet && r.URL.Path == "/api/events":
		if r.Header.Get("X-Tunn-Inspector-Token") != i.token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(i.list())
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/events/") && strings.HasSuffix(r.URL.Path, "/replay"):
		if r.Header.Get("X-Tunn-Inspector-Token") != i.token || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+i.host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		idString := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/events/"), "/replay")
		id, err := strconv.ParseUint(strings.Trim(idString, "/"), 10, 64)
		if err != nil {
			http.Error(w, "invalid delivery ID", http.StatusBadRequest)
			return
		}
		if _, err := i.replay(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

const inspectorHTML = `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>tunn inspector</title>
<style>
body{font:14px system-ui,sans-serif;max-width:1050px;margin:32px auto;padding:0 20px;color:#17202a}
h1{font-size:24px}p{color:#566}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #ddd}
tr[data-id]{cursor:pointer}tr[data-id]:hover{background:#f1f5f9}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7fa;padding:14px;border-radius:6px}
button{padding:8px 12px;cursor:pointer}small{color:#667}#detail{margin-top:24px}
</style>
<h1>tunn inspector</h1><p>Last 50 forwarded requests. Bodies are kept in this process only, up to 64 KiB each. Stopping tunn clears them. Replay sends a new request to the configured target and may repeat side effects.</p>
<table><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Duration</th><th>Bytes in / out</th></tr></thead><tbody id="events"></tbody></table>
<section id="detail"></section>
<script nonce="inspector">
const token=location.hash?decodeURIComponent(location.hash.slice(1)):sessionStorage.getItem('tunnInspectorToken');
if(location.hash){sessionStorage.setItem('tunnInspectorToken',token);history.replaceState(null,'',location.pathname)}
let selected=null,replaying=false;
async function refresh(){const res=await fetch('/api/events',{headers:{'X-Tunn-Inspector-Token':token}});if(!res.ok)return;
const events=await res.json();const body=document.querySelector('#events');body.replaceChildren();
for(const e of events.slice().reverse()){const row=document.createElement('tr');row.dataset.id=e.id;
for(const value of [new Date(e.at).toLocaleTimeString(),e.method,e.path,e.status||e.error,e.duration_ms+' ms',e.request_bytes+' / '+e.response_bytes]){
const cell=document.createElement('td');cell.textContent=value;row.append(cell)}row.onclick=()=>show(e);body.append(row)}
if(selected){const updated=events.find(e=>e.id===selected);if(updated)show(updated)}}
function show(e){selected=e.id;const box=document.querySelector('#detail');box.replaceChildren();
const title=document.createElement('h2');title.textContent=(e.replay_of?'Replay of #'+e.replay_of:'Delivery #'+e.id)+' · '+e.method+' '+e.path;box.append(title);
const note=document.createElement('small');note.textContent=e.truncated?'Body truncated; replay unavailable':(e.replayable?'Complete capture':'Incomplete capture; replay unavailable');box.append(note);
const head=document.createElement('pre');head.textContent=JSON.stringify(e.headers,null,2);box.append(head);
const payload=document.createElement('pre');const raw=Uint8Array.from(atob(e.body||''),c=>c.charCodeAt(0));payload.textContent=new TextDecoder().decode(raw);box.append(payload);
const button=document.createElement('button');button.textContent='Replay to configured target';button.disabled=!e.replayable||replaying;
button.onclick=async()=>{if(replaying)return;replaying=true;button.disabled=true;
try{const res=await fetch('/api/events/'+e.id+'/replay',{method:'POST',headers:{'X-Tunn-Inspector-Token':token}});
if(!res.ok)alert(await res.text())}finally{replaying=false;await refresh()}};box.append(button)}
refresh();setInterval(refresh,2000);
</script></html>`
