'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const dns = require('node:dns');
const readline = require('node:readline');
const {pathToFileURL} = require('node:url');
const {randomBytes} = require('node:crypto');
const modules = process.env.TUNN_MCP_NODE_MODULES;
const sdk = file => import(pathToFileURL(path.join(modules,'@modelcontextprotocol/sdk/dist/esm',file)).href);
const lines = readline.createInterface({input:process.stdin})[Symbol.asyncIterator]();
async function control(event) {
  console.log(JSON.stringify(event));
  const line = await lines.next();
  assert.equal(line.done,false);
  return JSON.parse(line.value);
}
(async () => {
  const {Client} = await sdk('client/index.js');
  const {StreamableHTTPClientTransport} = await sdk('client/streamableHttp.js');
  const {UnauthorizedError} = await sdk('client/auth.js');
  const endpoint = process.argv[2], base = new URL(endpoint).hostname.replace(/^tools\./,'');
  // Fixture DNS only; OAuth and MCP still see the canonical TLS origins.
  dns.lookup = (hostname, options, cb) => {
    if (typeof options === 'function') { cb=options; options={}; }
    if (hostname !== base && hostname !== `tools.${base}`) return cb(new Error('non-fixture DNS refused'));
    cb(null, options?.all ? [{address:'127.0.0.1',family:4}] : '127.0.0.1', 4);
  };
  const observations=[];
  const fetchFn = async (url, init) => {
    const u = new URL(typeof url === 'string' || url instanceof URL ? url : url.url);
    assert.ok(u.hostname === base || u.hostname === `tools.${base}`);
    const response = await fetch(url,init);
    const form = new URLSearchParams(init?.body instanceof URLSearchParams ? init.body : '');
    observations.push({path:u.pathname,status:response.status,grant:form.get('grant_type'),resource:form.get('resource')});
    return response;
  };
  const redirectUrl='http://127.0.0.1:17891/callback';
  const state=randomBytes(24).toString('hex');
  let info,tokens,verifier,callback,registrations=0;
  const provider={
    redirectUrl,
    clientMetadata:{client_name:'Official TypeScript SDK',redirect_uris:[redirectUrl],grant_types:['authorization_code','refresh_token'],response_types:['code'],token_endpoint_auth_method:'none',scope:'mcp'},
    state:()=>state,
    clientInformation:()=>info,
    saveClientInformation:value=>{info=value;registrations++;},
    tokens:()=>tokens,
    saveTokens:value=>{tokens=value;},
    saveCodeVerifier:value=>{verifier=value;}, codeVerifier:()=>verifier,
    redirectToAuthorization:async url=>{
      assert.equal(url.searchParams.get('code_challenge_method'),'S256');
      assert.equal(url.searchParams.get('resource'),endpoint);
      callback=(await control({event:'authorize',url:String(url),callback:redirectUrl})).callback;
      assert.equal(new URL(callback).searchParams.get('state'),state);
    },
    invalidateCredentials:scope=>{if (scope==='all'||scope==='client') info=undefined;if(scope==='all'||scope==='tokens')tokens=undefined;}
  };
  let transport=new StreamableHTTPClientTransport(new URL(endpoint),{authProvider:provider,fetch:fetchFn});
  let client=new Client({name:'official-ts-real-client',version:'1'});
  try {await client.connect(transport);assert.fail('unauthenticated connect succeeded');}
  catch(e){assert.ok(e instanceof UnauthorizedError);}
  await transport.finishAuth(new URL(callback).searchParams.get('code'));
  // An unsuccessful connect closes its transport; use a fresh transport with the saved SDK credentials.
  transport=new StreamableHTTPClientTransport(new URL(endpoint),{authProvider:provider,fetch:fetchFn});
  client=new Client({name:'official-ts-real-client',version:'1'});
  await client.connect(transport);
  try {
    assert.deepEqual((await client.listTools()).tools.map(t=>t.name),['echo']);
    assert.equal((await client.callTool({name:'echo',arguments:{message:'typescript-before-refresh'}})).content[0].text,'typescript-before-refresh');
    const old={...tokens};
    await control({event:'expire',access:old.access_token});
    assert.deepEqual((await client.listTools()).tools.map(t=>t.name),['echo']);
    assert.notEqual(tokens.access_token,old.access_token);
    assert.notEqual(tokens.refresh_token,old.refresh_token);
    assert.equal((await client.callTool({name:'echo',arguments:{message:'typescript-after-refresh'}})).content[0].text,'typescript-after-refresh');
    assert.equal(registrations,1);
    assert.ok(observations.some(x=>x.path==='/oauth/register'&&x.status===201));
    assert.ok(observations.some(x=>x.grant==='refresh_token'&&x.status===200));
    console.log(JSON.stringify({event:'result',sdk:'@modelcontextprotocol/sdk',version:require(path.join(modules,'@modelcontextprotocol/sdk/package.json')).version,registration:true,pkce:true,tools_list:true,tools_call:true,refresh:true,refresh_rotated:true,observations}));
  } finally {await client.close();}
  process.exit(0);
})().catch(e=>{console.error(e);process.exit(1);});
