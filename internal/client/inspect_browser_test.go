package client

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var inspectBrowserFixture = flag.String("inspect-browser-fixture", "", "write a serverless browser fixture under the clone's .scratch directory")

// The fixture uses the actual rendered UI and redacted server snapshots. Its
// mocked fetch responses exercise UI behavior; target dispatch is covered by
// the real HTTP/net.Pipe contract and the separate loopback tests.
func TestInspectBrowserFixture(t *testing.T) {
	if *inspectBrowserFixture == "" {
		return
	}
	path, err := filepath.Abs(*inspectBrowserFixture)
	if err != nil || !strings.Contains(path, string(filepath.Separator)+".scratch"+string(filepath.Separator)) {
		t.Fatal("browser fixture must be under .scratch")
	}
	i := inspectContractInspector()
	c := i.begin("GET", "/hook", map[string]string{"Content-Type": `<img src=x onerror="window.inspectorXSS=true">`})
	c.complete()
	c.finish(202, 2, "")
	c = i.begin("POST", "/secret?token=QUERY_SENTINEL", map[string]string{"Authorization": "Bearer HEADER_SENTINEL", "Cookie": "session=COOKIE_SENTINEL"})
	_, _ = c.Write([]byte("BODY_SENTINEL"))
	c.complete()
	c.finish(202, 2, "")
	for _, protocol := range []string{"websocket", "sse", "tcp"} {
		c = i.beginConnection(protocol, protocol, "GET", "/stream", nil)
		c.complete()
		c.finishReason(200, 4, "peer_closed")
	}
	c = i.begin("POST", "/truncated", nil)
	_, _ = c.Write([]byte(strings.Repeat("x", inspectBodyLimit+1)))
	c.complete()
	c.finish(200, 0, "")
	data, err := json.Marshal(i.list())
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := `<script nonce="inspector">
const fixtureEvents=EVENTS;
let fixtureDispatches=0,fixtureFail=false;
window.fetch=async(path,options={})=>{
 if(path==='/api/events')return {ok:true,json:async()=>fixtureEvents};
 if(path==='/api/metrics')return {ok:true,json:async()=>({active_streams:0,denied_admissions:2,reconnects:1,export_drops:0,history_evictions:0})};
 if(path.endsWith('/prepare'))return {ok:true,json:async()=>({action:'one-use-fixture-action'})};
 if(path.endsWith('/replay')){
  fixtureDispatches++;
  await new Promise(resolve=>setTimeout(resolve,100));
  if(fixtureFail)return {ok:false,text:async()=> 'fixture local target unavailable'};
  const event={...fixtureEvents[0],id:100,replay_of:1,status:202,response_bytes:2,terminal_reason:'complete'};
  fixtureEvents.push(event);return {ok:true,json:async()=>event};
 }
 throw new Error('Unexpected fixture fetch '+path);
};
</script>`
	bootstrap = strings.Replace(bootstrap, "EVENTS", string(data), 1)
	journey := `<script nonce="inspector">
async function fixtureWait(predicate){for(let n=0;n<100;n++){if(predicate())return;await new Promise(resolve=>setTimeout(resolve,10))}throw new Error('Browser fixture timed out')}
function fixtureAssert(value,message){if(!value)throw new Error(message)}
window.addEventListener('load',async()=>{
 const outcome=document.createElement('pre');outcome.id='acceptance';document.body.append(outcome);
 try{
  await fixtureWait(()=>document.querySelectorAll('tr[data-id]').length===6);
  fixtureAssert(!/HEADER_SENTINEL|COOKIE_SENTINEL|QUERY_SENTINEL|BODY_SENTINEL/.test(document.body.innerText),'Rendered token sentinel');
  fixtureAssert(fixtureDispatches===0,'Automatic replay occurred');
  document.querySelector('tr[data-id="1"]').click();
  fixtureAssert(!document.querySelector('#detail img'),'Captured header parsed as HTML');
  fixtureAssert(!window.inspectorXSS,'Captured content executed');
  document.querySelector('#replay').click();document.querySelector('#replay').click();
  await fixtureWait(()=>document.querySelector('#result').textContent.includes('HTTP 202'));
  fixtureAssert(fixtureDispatches===1,'Double click duplicated dispatch');
  fixtureAssert(document.querySelector('#detail').textContent.includes('Replay of #1'),'Replay result not selected');
  for(const id of [3,4,5,6]){document.querySelector('tr[data-id="'+id+'"]').click();fixtureAssert(document.querySelector('#replay').disabled,'Unsupported/truncated replay enabled')}
  document.querySelector('tr[data-id="2"]').click();
  fixtureAssert(document.querySelector('#detail').textContent.includes('explicit reconstruction'),'Redacted capture not explained');
  fixtureAssert(document.querySelectorAll('#detail textarea').length===2,'Missing header/body reconstruction fields');
  fixtureFail=true;document.querySelector('tr[data-id="1"]').click();document.querySelector('#replay').click();
  await fixtureWait(()=>document.querySelector('#result').textContent.includes('Replay error: fixture local target unavailable'));
  fixtureAssert(fixtureDispatches===2,'Error journey dispatch mismatch');
  fixtureAssert(!document.querySelector('#replay').disabled,'Replay stayed disabled after error');
  fixtureAssert(!/HEADER_SENTINEL|COOKIE_SENTINEL|QUERY_SENTINEL|BODY_SENTINEL/.test(document.body.innerText),'Detail token sentinel');
  outcome.dataset.inspectAcceptance='PASS';outcome.textContent='PASS: inspect, select, deliberate replay, visible 202/error, double click, redaction, HTML-as-data, WS/SSE/CONNECT/truncation';
 }catch(error){outcome.dataset.inspectAcceptance='FAIL';outcome.textContent=error.stack}
});
</script>`
	html := strings.Replace(inspectorHTML, `<script nonce="inspector">`, bootstrap+`<script nonce="inspector">`, 1)
	html = strings.Replace(html, "</body>", journey+"</body>", 1)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(html), 0600); err != nil {
		t.Fatal(err)
	}
}
