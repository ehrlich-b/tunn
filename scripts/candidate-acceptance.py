#!/usr/bin/env python3
"""Finite offline acceptance. Never executes a built CLI, binds or uses providers."""
import argparse,datetime,hashlib,json,os,pathlib,platform,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRATCH=ROOT/'.scratch'
PINS={'base':'642c06e7d4c28213fcb9a5a9850a6abfd111ab0b','sdk':'8a85ab8183665baf0ba89f04778fce7986c85e64','dogfix':'53d5d13234e66e5d60f705221989423f2b0f84b6'}
# All targets below have been inspected for memory-only/offline effects.
TEST_GATES={'test-sdk-unit','test-sdk-consumer','test-http-fidelity','test-candidate-cross','test-candidate-cli','test-candidate-dogfix','test-candidate-consumer','test-auth-contract','test-candidate-baseline','test-sdk-response-consumer'}
GATES=['test-candidate-provenance','test-sdk-unit','test-sdk-consumer','test-http-fidelity','test-candidate-cross','test-candidate-cli','test-candidate-dogfix','test-candidate-consumer','test-auth-contract','test-candidate-baseline','test-sdk-response-consumer','vet','build','test-candidate-build-info','diff-check']
OUTSIDE=[
 ('full-check','make -j1 check','full suite includes listeners and native child processes'),
 ('sdk-contract','make -j1 test-sdk-contract','required native relay/auth/HTTP/WebSocket acceptance'),
 ('sdk-exported-consumer-live','make -j1 test-sdk-response-consumer-live','real exported SDK importer and disposable loopback relay'),
 ('auth-loopback','make -j1 test-auth-loopback','real HTTPS OAuth lifecycle; memory TLS is separate evidence'),
 ('browser','make -j1 test-inspect-browser','Chromium forbidden in worker; outside-host disposable profile'),
 ('native-install-recovery','make -j1 test-install-recovery BUILD_OUTPUT=.scratch/bin/tunn BINARY_DIR=.scratch/bin','built CLI/process fixtures forbidden in worker'),
 ('native-install-two-paths','see docs/candidate/acceptance.md','built CLI/process installation and optional config runtime forbidden in worker'),
 ('deployed-activation','Bryan-controlled activation','production mutations forbidden to agents; candidate binary differs from deployed v37'),
 ('deployed-T+65-reconnect-revoke','Bryan-controlled T+65 reconnect/revoke','deployed client and elapsed-time evidence not available offline'),
 ('deployed-next-day-useful-task','Bryan-controlled next-day tools/call','requires next-day deployed consumer evidence'),
 ('w7-original-external-receipts','coordinator supplies immutable original receipts','original review/02:35 failure/later pass absent from committed input refs'),
]
def environment():
 env=os.environ.copy()
 for key in list(env):
  if key.startswith(('TUNN_','FLY_')) or key in {'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy','GOWORK','GOENV','GOFLAGS','GOROOT','GOOS','GOARCH','CGO_ENABLED'}:env.pop(key,None)
 paths={'GOCACHE':'cache/build','GOMODCACHE':'cache/mod','GOPATH':'gopath','GOTMPDIR':'tmp','TMPDIR':'tmp','npm_config_cache':'cache/npm','ZIG_GLOBAL_CACHE_DIR':'cache/zig','ZIG_LOCAL_CACHE_DIR':'cache/zig-local','PYTHONPYCACHEPREFIX':'cache/python','XDG_CONFIG_HOME':'isolated/config','XDG_CACHE_HOME':'isolated/cache','TUNN_CONFIG_DIR':'isolated/tunn'}
 for key,path in paths.items():
  value=(SCRATCH/path).resolve();value.mkdir(parents=True,exist_ok=True);env[key]=str(value)
 toolchain=SCRATCH/'cache/toolchain';env.update({'GOROOT':str(toolchain),'PATH':str(toolchain/'bin')+os.pathsep+env['PATH'],'GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOTELEMETRY':'off','GOFLAGS':'-p=2','GOMAXPROCS':'2','GO_TEST_FLAGS':'-json','GOWORK':'off','GOENV':'off','npm_config_offline':'true','PYTHONDONTWRITEBYTECODE':'1'})
 return env

def counts(log):
 passed=[];failed=[];skipped=[]
 for line in log.splitlines():
  try:event=json.loads(line)
  except ValueError:continue
  if not isinstance(event,dict) or not event.get('Test'):continue
  item=event.get('Package','')+':'+event['Test']
  if event.get('Action')=='pass':passed.append(item)
  elif event.get('Action')=='fail':failed.append(item)
  elif event.get('Action')=='skip':skipped.append(item)
 # Immutable consumer Makefile emits verbose output rather than JSON.
 for line in log.splitlines():
  line=line.lstrip()
  if line.startswith('--- PASS:'):passed.append(line.split()[2])
  elif line.startswith('--- FAIL:'):failed.append(line.split()[2])
  elif line.startswith('--- SKIP:'):skipped.append(line.split()[2])
 return {'passed':len(passed),'failed':failed,'skipped':skipped,'top_level_passed':sum('/' not in p.split(':',1)[-1] for p in passed)}

def run_gate(name,env,run,extra=None):
 cmd=['git','diff','--check'] if name=='diff-check' else ['make','-j1',name,'BUILD_OUTPUT=.scratch/tunn']
 if extra:cmd+=extra
 resource=['taskpolicy','-b','nice','-n','15'] if platform.system()=='Darwin' else ['nice','-n','15']
 started=time.monotonic();logpath=run/(str(len(list(run.glob('*.log')))).zfill(2)+'-'+name.replace('/','_')+'.log')
 try:
  with logpath.open('w') as out:p=subprocess.run(resource+cmd,cwd=ROOT,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=900)
  code=p.returncode
 except subprocess.TimeoutExpired:code=124
 log=logpath.read_text(errors='replace');c=counts(log)
 status='PASS' if code==0 else 'FAIL'
 if ('module lookup disabled by GOPROXY=off' in log or 'cannot find module' in log or 'toolchain' in log and 'cannot' in log) and code!=0:status='REQUIRED-UNRUN'
 if name in TEST_GATES and (c['passed']==0 or c['failed'] or c['skipped']):status='FAIL' if status!='REQUIRED-UNRUN' else status
 return {'gate':name,'status':status,'command':cmd,'exit_code':code,'elapsed_seconds':round(time.monotonic()-started,3),'counts':c,'log':str(logpath),'log_sha256':hashlib.sha256(logpath.read_bytes()).hexdigest()}

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,default=None);p.add_argument('--gates',nargs='+',choices=GATES);p.add_argument('--install-layout',action='store_true');a=p.parse_args()
 if a.output is not None and a.output.exists():raise SystemExit('receipt already exists; select a new path to preserve it')
 now=datetime.datetime.now(datetime.timezone.utc);run=SCRATCH/'logs'/('acceptance-'+now.strftime('%Y%m%dT%H%M%S%fZ'));run.mkdir(parents=True)
 result={'schema':1,'started_utc':now.isoformat(),'pins':PINS,'candidate_source_sha':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'gates':[],'required_unrun':[{'gate':gate,'status':'REQUIRED-UNRUN','command':cmd,'reason':reason} for gate,cmd,reason in OUTSIDE],'limits':{'threads':2,'one_heavy_command':True,'offline':True,'native_process_acceptance':False},'run_directory':str(run)}
 env=environment()
 if not (SCRATCH/'cache/toolchain/bin/go').exists():
  result['gates']=[{'gate':g,'status':'REQUIRED-UNRUN','reason':'clone-local Go toolchain not staged'} for g in a.gates or GATES]
 else:
  for gate in a.gates or GATES:
   receipt=run_gate(gate,env,run);result['gates'].append(receipt);print(gate+': '+receipt['status']+' ('+str(receipt['counts']['passed'])+' test/subtest passes)',flush=True)
  if a.install_layout:
   for index,name in enumerate(['first install with spaces','second install with spaces'],1):
    dest=SCRATCH/'installation'/name/'tunn';dest.parent.mkdir(parents=True,exist_ok=True)
    receipt=run_gate('build',env,run,extra=['BUILD_OUTPUT='+str(dest)]);receipt['gate']='build-install-path-'+str(index)
    if dest.exists():receipt['binary_sha256']=hashlib.sha256(dest.read_bytes()).hexdigest();receipt['binary_path']=str(dest)
    result['gates'].append(receipt);print(receipt['gate']+': '+receipt['status'],flush=True)
 binary=SCRATCH/'tunn'
 if binary.exists():result['binary']={'path':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'bytes':binary.stat().st_size,'runtime_executed':False}
 result['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();selected_pass=bool(result['gates']) and all(g['status']=='PASS' for g in result['gates'])
 selected={g['gate'] for g in result['gates']}
 result['unselected_local_gates']=[{'gate':g,'status':'REQUIRED-UNRUN','reason':'not selected in this checkpoint invocation'} for g in GATES if g not in selected]
 result['outcome']='ready-local-externally-pending' if selected_pass and not result['unselected_local_gates'] else 'checkpoint-pass' if selected_pass else 'partial'
 a.output=(a.output or SCRATCH/'receipts'/('result-'+now.strftime('%Y%m%dT%H%M%S%fZ')+'.json')).resolve();assert a.output.is_relative_to(SCRATCH.resolve());a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print('receipt: '+str(a.output),flush=True)
 return 0 if selected_pass else 1
if __name__=='__main__':raise SystemExit(main())
