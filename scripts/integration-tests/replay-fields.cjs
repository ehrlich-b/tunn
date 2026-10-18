'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname,'../../internal/inspection/replay_validation.js'),'utf8');
vm.runInThisContext(source);
const event = {path:'/hook?a=%5Bredacted%5D&a=%5Bredacted%5D&z=%5Bredacted%5D', query_redacted:true,
  headers:{Accept:'application/json','X-Signature':'[redacted]'},redacted_headers:['X-Signature'],body_captured:false,request_bytes:4};
const fields = {path:'/hook?z=%ff&a=one+two&a=%2f',headers:'{"Accept":"application/json","x-signature":"  exact value\\t "}',body:'AAH+/w==',bodyFormat:'base64'};
let count = 0;
function invalid(field, change, message, capture = event) {
  const checked = replayFields(capture,{...fields,...change});
  const error = checked.errors.find(error => error.field === field);
  assert.ok(error,JSON.stringify(change));
  assert.equal(error.message,message + ' Request not sent.'); count++;
}
const valid = replayFields(event,fields);
assert.deepEqual(valid.errors,[]);
assert.equal(valid.input.path,fields.path);
assert.equal(valid.input.headers['x-signature'],'  exact value\t ');
assert.equal(valid.input.body,fields.body); count++;
for (const headers of ['{','null','[]','42','"headers"']) invalid('headers',{headers},'Headers: Enter a JSON object of header names and text values.');
invalid('headers',{headers:'{}'},'Headers: Restore Accept, X-Signature.');
invalid('headers',{headers:'{"Accept":"application/json","X-Signature":null}'},'Headers: X-Signature must be text.');
invalid('headers',{headers:'{"Accept":"application/json","X-Signature":"[redacted]"}'},'Headers: Restore X-Signature.');
invalid('headers',{headers:'{"Accept":"application/json","X-Signature":"ok","x-signature":"ok"}'},'Headers: Remove the duplicate X-Signature header.');
invalid('headers',{headers:'{"Accept":"text/plain","X-Signature":"ok"}'},'Headers: Keep the captured Accept value.');
invalid('headers',{headers:JSON.stringify({...event.headers,'X-Signature':'x'.repeat(1025)})},'Headers: X-Signature exceeds 1024 bytes.');
invalid('headers',{headers:JSON.stringify({...event.headers,'X-Signature':'é'.repeat(513)})},'Headers: X-Signature exceeds 1024 bytes.');
invalid('headers',{headers:JSON.stringify({...event.headers,'X-Signature':'ok\r\nInjected: yes'})},'Headers: X-Signature cannot contain line breaks or NUL.');
invalid('headers',{headers:JSON.stringify({...event.headers,'X-Signature':'bad\x01value'})},'Headers: X-Signature cannot contain control characters.');
invalid('headers',{headers:JSON.stringify({...event.headers,'X-Signature':'tunn_app_example'})},'Headers: Restore X-Signature without platform credentials.');
invalid('headers',{headers:JSON.stringify({...event.headers,'Extra':'ok','X-Signature':'ok'})},'Headers: Keep only the original header names.');
invalid('path',{path:''},'Path and query: Restore the original path and query.');
invalid('path',{path:'/hook?z='+ 'é'.repeat(1021)},'Path and query: Use at most 2048 bytes.');
invalid('path',{path:'/hook'},'Path and query: Keep every original query field.');
invalid('path',{path:'/other?a=1&a=2&z=3'},'Path and query: Keep the original path.');
invalid('path',{path:'/hook?a=1&z=3'},'Path and query: Keep every original query field.');
invalid('path',{path:'/hook?a=1&a=2&z=%5bredacted%5d'},'Path and query: Restore every hidden value.');
invalid('path',{path:'/hook?a=1&a=2&z=tunn_ep_example'},'Path and query: Restore every hidden value.');
invalid('path',{path:'/hook?a=1&a=2&z=%x'},'Path and query: Use a valid original path and query.');
invalid('path',{path:'/hook?a=1&a=2&z=3;extra=4'},'Path and query: Use a valid query.');
invalid('path',{path:'//hook?a=1&a=2&z=3'},'Path and query: Use a valid original path and query.');
invalid('body',{body:''},'Body: Restore the original body.');
for (const body of ['@@@','AAH+/w','AAH+ w==']) invalid('body',{body},'Body: Enter valid Base64.');
invalid('body',{body:'AA=='},'Body: Restore exactly 4 bytes.');
invalid('body',{body:Buffer.alloc(65537).toString('base64')},'Body: Use at most 64 KiB.');
invalid('body',{body:'é'.repeat(32769),bodyFormat:'text'},'Body: Use at most 64 KiB.');
invalid('body',{body:'tunn_sk_example',bodyFormat:'text'},'Body: Remove platform credentials.',{...event,request_bytes:15});
for (const [body,bodyFormat,bytes] of [['é\r\n','text',4],['AAH+\r\n/w==','base64',4],[Buffer.alloc(65536).toString('base64'),'base64',65536]]) {
  const checked = replayFields({...event,request_bytes:bytes},{...fields,body,bodyFormat});
  assert.deepEqual(checked.errors,[]);
  assert.equal(checked.input.body,bodyFormat==='text'?Buffer.from(body).toString('base64'):body); count++;
}
const specialPath = fields.path.replace('/hook?',()=>'/hook/$&?');
const special = replayFields({...event,path:event.path.replace('/hook?',()=>'/hook/$&?')},{...fields,path:specialPath});
assert.deepEqual(special.errors,[]);assert.equal(special.input.path,specialPath);count++;
for (const rawPath of ['/items/(1)', '/Products(1)', '/a!b', "/a'b*c", '/list[0]', '/a%2Fb', '/a%2fb']) {
  const capture = {...event,path:rawPath+'?x=%5Bredacted%5D'};
  const restoredPath = rawPath+'?x=one+two%2f%ff';
  const checked = replayFields(capture,{...fields,path:restoredPath});
  assert.deepEqual(checked.errors,[],rawPath);
  assert.equal(checked.input.path,restoredPath); count++;
  invalid('path',{path:rawPath+'/changed?x=value'},'Path and query: Keep the original path.',capture);
}
// Equivalent decoded paths still must keep the captured escaping, as Reconstruct requires.
invalid('path',{path:'/a%21b?x=value'},'Path and query: Keep the original path.',{...event,path:'/a!b?x=%5Bredacted%5D'});
assert.deepEqual(replayFields({path:'/empty',headers:{},request_bytes:0},{}),{input:{},errors:[]}); count++;
console.log(JSON.stringify({result:'PASS',cases:count,checks:'exact errors, missing fields, markers, malformed JSON/Base64/URI, byte limits, binary and UTF-8 preservation'}));
