#!/usr/bin/env python3
"""Validate frozen pins, consumers and integration scope entirely from Git."""
import argparse, hashlib, json, pathlib, re, subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
def git(*args): return subprocess.check_output(['git',*args],cwd=ROOT,text=True).strip()
def verify():
 inventory=json.loads((ROOT/'docs/candidate/inventory.json').read_text())
 base=inventory['base']; head=git('rev-parse','HEAD'); checks=[]
 assert git('rev-parse','merge/main')==base
 for name,input in inventory['inputs'].items():
  pin=input['pin']; assert git('rev-parse','refs/wave8/inputs/'+name)==pin
  subprocess.run(['git','merge-base','--is-ancestor',pin,head],cwd=ROOT,check=True)
  checks.append({'gate':'reachable-'+name,'status':'PASS','pin':pin})
 for capability in inventory['capabilities']:
  subprocess.run(['git','merge-base','--is-ancestor',capability['commit'],head],cwd=ROOT,check=True)
  source=git('show',head+':'+capability['consumer'])
  assert re.search(r'^func '+capability['test']+r'\(',source,re.M),capability
  checks.append({'gate':capability['capability'],'status':'PASS','commit':capability['commit'],'consumer':capability['consumer'],'test':capability['test']})
 fix=inventory['terminal_fix']['commit']
 assert git('rev-list',head).splitlines().count(fix)==1
 source=git('show',head+':internal/host/webproxy.go')
 assert source.count('panic(http.ErrAbortHandler)')==1
 proxy=source[source.index('func (p *ProxyServer) proxyToLocal('):source.index('// Abort the downstream')]
 assert 'panic(' not in proxy and 'return proxyErr' in proxy
 allowed=set()
 for input in inventory['inputs'].values():
  merge=git('merge-base',base,input['pin'])
  allowed.update(git('diff','--name-only',merge,input['pin']).splitlines())
 changed=set(git('diff','--name-only',base,head).splitlines())
 owned=lambda name:name.startswith('docs/candidate/') or name.startswith('scripts/candidate-') or name in {'internal/host/candidate_integration_test.go','candidate_cli_test.go','sdk/candidate_fixture.go','internal/config/ops_test.go'} or name.startswith('sdk/testdata/candidate-consumer/')
 unexpected=sorted(name for name in changed-allowed if not owned(name))
 assert not unexpected,unexpected
 deployment=[name for name in changed if name.startswith('deploy/') or name in {'fly.toml','fly.toml.dist','Dockerfile','docker-compose.yml'}]
 assert not deployment,deployment
 # The handler and authorizer remain byte-identical to the pinned base.
 for path in ['sdk/handler.go','internal/host/mcp_oauth.go','internal/host/mcp_oauth_store.go']:
  assert git('show',base+':'+path)==git('show',head+':'+path),path
 checks.append({'gate':'terminal-fix-once-and-preserved-base-contracts','status':'PASS','commit':fix})
 return {'schema':1,'base':base,'candidate_source_sha':head,'frozen_inventory_sha256':hashlib.sha256((ROOT/'docs/candidate/inventory.json').read_bytes()).hexdigest(),'changed_files':sorted(changed),'checks':checks}
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--verify',action='store_true');parser.add_argument('--output',type=pathlib.Path);args=parser.parse_args()
 result=verify();data=json.dumps(result,indent=2)+'\n'
 if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(data)
 print(data)
