#!/usr/bin/env python3
"""Bounded loopback relay comparison. Python 3 + Go; no installed dependencies.

make bench-relay BENCH_ARGS='--work-dir /absolute/scratch --output /absolute/evidence'
The Go driver is compiled through an overlay: the checkout is never modified.
--self-test-broken-origin deliberately returns nonzero on a truncated 1 KiB body.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import sys
import tarfile
import time
import shutil
import threading
import urllib.request

FRP_VERSION = "0.72.0"
FRP_SHA256 = "daf719b32ca2778770bb92955e231a07414d754378b9af328aa2642862479804"
FRP_URL = (f"https://github.com/fatedier/frp/releases/download/v{FRP_VERSION}/"
           f"frp_{FRP_VERSION}_linux_amd64.tar.gz")

# Compiled in package host so the fixture exercises the very same HTTP/gRPC
# data path as timing_dogfood_test.go, without adding a production entry point.
DRIVER = r'''
package host

import (
 "context"
 "crypto/tls"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "net/url"
 "os"
 "os/exec"
 "path/filepath"
 "strconv"
 "sync"
 "testing"
 "time"

 "github.com/ehrlich-b/tunn/internal/client"
 "github.com/ehrlich-b/tunn/internal/config"
 pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
 "google.golang.org/grpc"
 "google.golang.org/grpc/credentials"
)

type rbSample struct {
 MS float64 `json:"ms"`
 Error string `json:"error,omitempty"`
}
type rbRun struct {
 Path string `json:"path"`
 Bytes int `json:"bytes"`
 Concurrency int `json:"concurrency"`
 Round int `json:"round"`
 Slow bool `json:"slow"`
 Kind string `json:"kind"`
 Seconds float64 `json:"seconds"`
 Samples []rbSample `json:"samples"`
 SlowBytes int64 `json:"slow_bytes,omitempty"`
 SlowSeconds float64 `json:"slow_seconds,omitempty"`
 SlowTargetBPS int `json:"slow_target_bps,omitempty"`
 SlowRequestedBytes int `json:"slow_requested_bytes,omitempty"`
}

func rbTransport() *http.Transport {
 return &http.Transport{Proxy:nil, MaxIdleConns:200, MaxIdleConnsPerHost:100,
  MaxConnsPerHost:100, DisableCompression:true}
}
func rbFetch(c *http.Client, base string, size int) rbSample {
 start:=time.Now()
 r,err:=c.Get(base+"/?size="+strconv.Itoa(size))
 if err==nil {
  var n int64
  n,err=io.Copy(io.Discard,r.Body)
  r.Body.Close()
  if err==nil && (r.StatusCode!=200 || n!=int64(size)) {
   err=fmt.Errorf("invalid response status=%d bytes=%d want=%d",r.StatusCode,n,size)
  }
 }
 s:=rbSample{MS:float64(time.Since(start))/float64(time.Millisecond)}
 if err!=nil {s.Error=err.Error()}
 return s
}
func rbWave(base string,size,concurrency,each int,timeout time.Duration,warmConnections bool) rbRun {
 tr:=rbTransport(); defer tr.CloseIdleConnections()
 c:=&http.Client{Transport:tr,Timeout:timeout}
 var wg sync.WaitGroup
 if warmConnections {
  // Throughput cases warm the pool; both victim conditions use fresh pools.
  warm:=make(chan rbSample,concurrency)
  for i:=0;i<concurrency;i++ {wg.Add(1);go func(){defer wg.Done();warm<-rbFetch(c,base,1024)}()}
  wg.Wait();close(warm)
  for s:=range warm {if s.Error!="" {return rbRun{Bytes:size,Concurrency:concurrency,Samples:[]rbSample{s}}}}
  time.Sleep(20*time.Millisecond) // allow terminal relay bookkeeping to finish
 }
 ready:=make(chan struct{})
 results:=make(chan rbSample,concurrency*each)
 for i:=0;i<concurrency;i++ {wg.Add(1);go func(){
  defer wg.Done();<-ready
  for j:=0;j<each;j++ {results<-rbFetch(c,base,size)}
 }()}
 start:=time.Now();close(ready);wg.Wait()
 elapsed:=time.Since(start).Seconds();close(results)
 run:=rbRun{Bytes:size,Concurrency:concurrency,Seconds:elapsed}
 for s:=range results {run.Samples=append(run.Samples,s)}
 return run
}
func rbAssert(t *testing.T,run rbRun) {
 t.Helper()
 for _,s:=range run.Samples {if s.Error!="" {t.Fatalf("%s %d bytes: %s",run.Path,run.Bytes,s.Error)}}
}
func rbTunn(t *testing.T,origin string)(string,func()) {
 t.Helper()
 certSource:=httptest.NewTLSServer(http.NotFoundHandler())
 cert:=certSource.TLS.Certificates[0];certSource.Close()
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil {t.Fatal(err)}
 ts:=NewTunnelServer(&config.Config{PublicMode:true,Domain:"relay-bench.test"},nil,nil,nil)
 gs:=grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates:[]tls.Certificate{cert}})))
 pb.RegisterTunnelServiceServer(gs,ts)
 go func(){_ = gs.Serve(listener)}()
 ctx,cancel:=context.WithCancel(context.Background())
 publisher:=&client.ServeClient{TunnelID:"relay-bench",TargetURL:origin,ServerAddr:listener.Addr().String(),Insecure:true}
 done:=make(chan error,1);go func(){done<-publisher.Run(ctx)}()
 var tunnel *TunnelConnection
 for end:=time.Now().Add(10*time.Second);time.Now().Before(end); {
  if tc,ok:=ts.GetTunnel("relay-bench");ok {tunnel=tc;break};time.Sleep(time.Millisecond*10)
 }
 if tunnel==nil {cancel();gs.Stop();t.Fatal("publisher registration timeout")}
 // Isolate transport overhead from hosted-plan token buckets.
 tunnel.rateMu.Lock();tunnel.rateLimiter=nil;tunnel.rateMu.Unlock()
 proxy:=&ProxyServer{}
 ingress:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if err:=proxy.proxyHTTPOverGRPC(w,r,tunnel);err!=nil {return}
 }))
 return ingress.URL,func(){
  cancel();gs.Stop();ingress.CloseClientConnections();ingress.Close()
  select {case <-done:case <-time.After(5*time.Second):t.Error("publisher did not stop")}
 }
}
func rbPort(t *testing.T) int {
 l,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil {t.Fatal(e)}
 p:=l.Addr().(*net.TCPAddr).Port;l.Close();return p
}
func rbFrp(t *testing.T,origin string)(string,func()) {
 t.Helper()
 dir:=os.Getenv("RB_WORK");bin:=os.Getenv("RB_FRP")
 port,remote:=rbPort(t),rbPort(t)
 u,_:=url.Parse(origin);_,local,_:=net.SplitHostPort(u.Host)
 server:=fmt.Sprintf("bindAddr = \"127.0.0.1\"\nbindPort = %d\nproxyBindAddr = \"127.0.0.1\"\n",port)
 publisher:=fmt.Sprintf("serverAddr = \"127.0.0.1\"\nserverPort = %d\nloginFailExit = true\ntransport.tcpMux = true\ntransport.tls.enable = true\n[[proxies]]\nname = \"relay-bench\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %s\nremotePort = %d\n",port,local,remote)
 start:=func(name,conf string)*exec.Cmd {
  cfg:=filepath.Join(dir,name+".toml")
  if e:=os.WriteFile(cfg,[]byte(conf),0600);e!=nil {t.Fatal(e)}
  log,e:=os.Create(filepath.Join(dir,name+".log"));if e!=nil {t.Fatal(e)}
  cmd:=exec.Command(filepath.Join(bin,name),"-c",cfg);cmd.Stdout=log;cmd.Stderr=log
  if e:=cmd.Start();e!=nil {log.Close();t.Fatal(e)}
  t.Cleanup(func(){_ = cmd.Process.Kill();_ = cmd.Wait();log.Close()})
  return cmd
 }
 wait:=func(port int){
  for end:=time.Now().Add(10*time.Second);time.Now().Before(end); {
   c,e:=net.DialTimeout("tcp",fmt.Sprintf("127.0.0.1:%d",port),100*time.Millisecond)
   if e==nil {c.Close();return};time.Sleep(20*time.Millisecond)
  };t.Fatal("frp listener did not start; see frps/frpc.log")
 }
 s:=start("frps",server);wait(port);c:=start("frpc",publisher);wait(remote)
 return fmt.Sprintf("http://127.0.0.1:%d",remote),func(){_ = c.Process.Kill();_ = s.Process.Kill()}
}

func TestRelayBenchDriver(t *testing.T) {
 // A generated body avoids holding 100 separate 100 MiB buffers in memory.
 origin:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  size,e:=strconv.Atoi(r.URL.Query().Get("size"));if e!=nil || size<1 || size>100*1024*1024 {http.Error(w,"size",400);return}
  w.Header().Set("Content-Length",strconv.Itoa(size))
  if os.Getenv("RB_BROKEN")=="1" {return} // deliberate truncated 1 KiB response
  block:=make([]byte,32*1024)
  for size>0 {n:=len(block);if size<n {n=size};if _,e:=w.Write(block[:n]);e!=nil {return};size-=n}
 }))
 defer origin.Close()
 if os.Getenv("RB_BROKEN")=="1" {
  run:=rbWave(origin.URL,1024,1,1,2*time.Second,true);run.Path="broken-origin";rbAssert(t,run);t.Fatal("broken origin was accepted")
 }
 tunn,stopTunn:=rbTunn(t,origin.URL);defer stopTunn()
 frp,stopFrp:=rbFrp(t,origin.URL);defer stopFrp()
 bases:=map[string]string{"direct":origin.URL,"tunn":tunn,"frp":frp}
 var runs []rbRun
 emit:=func(){
  b,e:=json.MarshalIndent(runs,"","  ");if e!=nil {t.Fatal(e)}
  if e=os.WriteFile(os.Getenv("RB_RAW"),b,0600);e!=nil {t.Fatal(e)}
 }
 for round:=0;round<5;round++ {
  for _,size:=range []int{1024,1024*1024,100*1024*1024} {for _,parallel:=range []int{1,100} {
   names:=[]string{"direct","tunn","frp"}
   // Rotate measurement order to reduce a fixed warm-cache/temperature bias.
   for offset:=0;offset<3;offset++ {
    name:=names[(round+offset)%3];each:=1
    if parallel==1 {each=100;if size>1024 {each=10}} else if size==1024 {each=2}
    t.Logf("round=%d path=%s bytes=%d concurrency=%d",round+1,name,size,parallel)
    run:=rbWave(bases[name],size,parallel,each,120*time.Second,true)
    run.Path=name;run.Round=round+1;run.Kind="throughput"
    rbAssert(t,run);runs=append(runs,run);emit()
   }
  }}
 }
 // Each observation requests 100 MiB, but cancels it after a bounded window:
 // completing that transfer at 10,000 B/s would take about 2.9 hours.
 for _,name:=range []string{"tunn","frp"} {for round:=1;round<=5;round++ {
  base:=bases[name]
  baseline:=rbWave(base,1024,99,1,3*time.Second,false)
  baseline.Path=name;baseline.Round=round;baseline.Kind="victim"
  rbAssert(t,baseline);runs=append(runs,baseline)
  u,_:=url.Parse(base)
  conn,e:=net.Dial("tcp",u.Host);if e!=nil {t.Fatal(e)}
  if tcp,ok:=conn.(*net.TCPConn);ok {if e=tcp.SetReadBuffer(16*1024);e!=nil {t.Fatal(e)}}
  _ = conn.SetDeadline(time.Now().Add(15*time.Second))
  _,e=fmt.Fprintf(conn,"GET /?size=104857600 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",u.Host)
  if e!=nil {conn.Close();t.Fatal(e)}
  // Read headers bytewise so no buffered prefetch drains body at full speed.
  var header []byte;one:=make([]byte,1)
  for len(header)<16384 {
   if _,e=io.ReadFull(conn,one);e!=nil {conn.Close();t.Fatal(e)}
   header=append(header,one[0]);n:=len(header)
   if n>=4 && string(header[n-4:])=="\r\n\r\n" {break}
  }
  if string(header[:12])!="HTTP/1.1 200" {conn.Close();t.Fatal("slow reader did not receive 200")}
  slowStart:=time.Now();done:=make(chan struct{});stop:=make(chan struct{});var slowBytes int64
  go func(){defer close(done);ticker:=time.NewTicker(100*time.Millisecond);defer ticker.Stop();buf:=make([]byte,1000)
   for {select {case <-stop:return;case <-ticker.C:
    n,e:=io.ReadFull(conn,buf);slowBytes+=int64(n);if e!=nil {return}
   }}
  }()
  time.Sleep(2*time.Second) // let TCP and relay buffers fill before victim requests
  // Match baseline preparation; warming here could block on the slow reader.
  run:=rbWave(base,1024,99,1,3*time.Second,false)
  run.Path=name;run.Round=round;run.Slow=true;run.Kind="victim"
  close(stop);conn.Close();<-done
  run.SlowBytes=slowBytes;run.SlowSeconds=time.Since(slowStart).Seconds()
  run.SlowTargetBPS=10000;run.SlowRequestedBytes=100*1024*1024
  rate:=float64(slowBytes)/run.SlowSeconds
  if rate<9500 || rate>10500 {t.Fatalf("slow reader missed 10 KB/s target: %.1f B/s",rate)}
  // Deadline errors are observations (right-censored latencies), never successes.
  for _,s:=range run.Samples {if s.Error!="" {
   // Other failures indicate a bad harness or broken response, rather than HOL.
   if !containsDeadline(s.Error) {t.Fatalf("victim error: %s",s.Error)}
  }}
  runs=append(runs,run);emit()
  // Closing the slow socket releases the shared tunnel before the next round.
  time.Sleep(100*time.Millisecond)
 }}
}
func containsDeadline(s string) bool {
 for i:=0;i+len("Client.Timeout")<=len(s);i++ {if s[i:i+len("Client.Timeout")]=="Client.Timeout" {return true}}
 return false
}
'''


def run(command, *, cwd, env=None, timeout=120):
    print("+ " + " ".join(map(str, command)), flush=True)
    return subprocess.run(command, cwd=cwd, env=env, check=True, timeout=timeout)


def release(work):
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise RuntimeError("pinned release supports Linux amd64; supply a reviewed release for this host")
    archive = work / f"frp_{FRP_VERSION}_linux_amd64.tar.gz"
    if not archive.exists():
        with urllib.request.urlopen(FRP_URL, timeout=60) as source, archive.open("wb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != FRP_SHA256:
        raise RuntimeError(f"release checksum mismatch: {actual}")
    dest = work / "release"
    dest.mkdir(exist_ok=True)
    with tarfile.open(archive) as tar:
        for name in ("frpc", "frps"):
            member = tar.getmember(f"frp_{FRP_VERSION}_linux_amd64/{name}")
            with tar.extractfile(member) as source, (dest / name).open("wb") as target:
                target.write(source.read())
            (dest / name).chmod(0o700)
    return dest


def quantile(values, p):
    values = sorted(values)
    import math
    return values[max(0, math.ceil(len(values) * p) - 1)]


def metrics(row):
    samples = row["samples"]
    return {"p50": quantile([s["ms"] for s in samples], .50),
            "p99": quantile([s["ms"] for s in samples], .99),
            "MB/s": sum(row["bytes"] for s in samples if not s.get("error")) / row["seconds"] / 1e6}


def spread(values):
    return f"{statistics.median(values):.3f} [{min(values):.3f}, {max(values):.3f}]"


def report(data, output):
    rows = data["runs"]
    lines = ["# Loopback relay benchmark", "", "All figures are median [min, max] of five runs. Latency is full-body milliseconds; MB/s uses decimal MB and whole-wave wall time. Added latency subtracts the matching direct run's percentile (not per-request paired differences). Percentiles use nearest rank. Raw request latencies, errors, elapsed times and slow-reader progress are in [bench.json](bench.json).", "",
             "| Body | Concurrency | Path | p50 ms | p99 ms | Added p50 ms | Added p99 ms | MB/s |", "|---|---:|---|---:|---:|---:|---:|---:|"]
    for size in (1024, 1048576, 104857600):
        for concurrency in (1, 100):
            direct = [r for r in rows if r["kind"] == "throughput" and r["bytes"] == size and r["concurrency"] == concurrency and r["path"] == "direct"]
            for name in ("direct", "tunn", "frp"):
                group = [r for r in rows if r["kind"] == "throughput" and r["bytes"] == size and r["concurrency"] == concurrency and r["path"] == name]
                values = [metrics(r) for r in group]
                added = {q: [metrics(r)[q] - metrics(next(d for d in direct if d["round"] == r["round"]))[q] for r in group] for q in ("p50", "p99")}
                cells = [str(size), str(concurrency), name, spread([v["p50"] for v in values]), spread([v["p99"] for v in values]), spread(added["p50"]), spread(added["p99"]), spread([v["MB/s"] for v in values])]
                lines.append("| " + " | ".join(cells) + " |")
    lines += ["", "## Slow reader", "", "One separate socket requests 100 MiB on the same publisher tunnel and reads 1,000 bytes every 100 ms (10 KB/s = 10,000 B/s), with a 16 KiB socket receive buffer. Achieved rate must be within 5% of 10,000 B/s or the run fails. After two seconds, 99 concurrent victims request 1 KiB each. The slow transfer is cancelled after the victim wave; completing it would exceed the runtime budget. Each victim has a three-second deadline; a timed-out p99 is reported as a lower bound, and errors remain in raw data. Baseline waves run on the same tunnel immediately before each observation. Both baseline and slow-reader victim waves use fresh connection pools without warm-up, so connection setup is included identically in both conditions. The slow socket plus 99 victims stays within the existing 100-connection tunnel limit.", "", "| Path | Slow reader | Victim p99 ms median [min, max] | Timed out / 495 |", "|---|---|---:|---:|"]
    for name in ("tunn", "frp"):
        for slow in (False, True):
            group = [r for r in rows if r["kind"] == "victim" and r["path"] == name and r["slow"] == slow]
            errors = sum(bool(s.get("error")) for r in group for s in r["samples"])
            # The nearest-rank percentile is censored when its rank falls in
            # the timed-out tail (one timeout suffices for 99 samples at p99).
            censored = any(quantile([bool(s.get("error")) for s in r["samples"]], .99) for r in group)
            lines.append(f"| {name} | {slow} | {'≥ ' if censored else ''}{spread([metrics(r)['p99'] for r in group])} | {errors} |")
    lines += ["", "## Method and limits", "",
              "The generated Go overlay runs the existing relay HTTP/gRPC data path and the real ServeClient, with TLS on the publisher link. HTTP ingress and origin use HTTP/1.1 on literal loopback; tunn's minimal ingress calls proxyHTTPOverGRPC directly, excluding public routing, authentication, quotas and TLS ingress. The fixture disables the per-tunnel bandwidth token bucket before measurement to isolate transport overhead; production limits are unchanged. frp uses its public binary release, TCP proxy mode, tcpMux=true and TLS enabled on the publisher link; compression is off. All paths share the same Go origin and load generator. This measures relay transport overhead on this machine, not complete product ingress or remote-network behavior.", "",
              "Each throughput wave warms connections with 1 KiB requests before timing. Single concurrency uses 100 requests for 1 KiB, 10 for larger bodies; concurrency 100 uses two requests per worker for 1 KiB, one for larger bodies. Thus single/large-body p99 is the maximum of only ten samples per run, not a precise tail estimate. Path order rotates each round. Slow-reader failures are right-censored, with no invented completion latency. No relay implementation is changed.", "", "## Machine and provenance", "", "```json", json.dumps(data["machine"], indent=2), "```", "", f"frp release: {FRP_URL}", f"SHA-256: `{FRP_SHA256}`", f"Committed HEAD: `{data['head']}`", f"Elapsed including setup/build: {data['elapsed_seconds']:.3f} seconds; niceness: {data['niceness']}.", "", "## Commands", "", "```sh", data["command"], "# Deliberately truncated 1 KiB origin; expected nonzero:", data["self_test_command"], "```", "", "Driver source, overlay mapping, build log, process logs and release configuration are retained in the specified work directory. All services bind to 127.0.0.1; no hosted endpoint is measured."]
    (output / "BENCH.md").write_text("\n".join(lines) + "\n")


def capacity_report(data, output):
    lines = ["# Single-relay capacity", "", "Measured on loopback with a separate relay, publisher/origin process, and open-loop visitor process. All services bind to 127.0.0.1. TLS is enabled on ingress and publisher gRPC. Tiny self-tests validate HTTP correctness and report timing spikes as warnings; full measurements enforce the timing thresholds below. The relay is pinned with taskset; GOMEMLIMIT is a soft Go runtime target, not a VM memory cap. A parent watchdog stops the relay if sampled RSS exceeds the stated memory budget; it cannot reproduce a kernel OOM kill. No production service is contacted.", "",
             f"Shape: {data['cpus']} CPU(s), GOMEMLIMIT={data['gomemlimit']}, RSS budget {data['rss_budget_mib']} MiB. Body: {data['body_bytes']} bytes, distributed round-robin over {data['traffic_tunnels']} tunnels; each traffic step offers arrivals for {data['step_seconds']} seconds. Idle stages settle for three seconds after registration. If 1,000 RPS passes, a bounded extension at 1,250, 1,500 and 2,000 RPS stops at the first failure to locate a breaking point. This is a bounded capacity observation, not a long soak or Fly shared-CPU guarantee.", "",
             "The fixture uses real ServeClient publishers, production host routing, HTTP admission, transport and bandwidth limits. Each publisher authenticates with a fixture-signed JWT and a distinct free account through production registration and durable public web sharing. Account lookup, plan quota admission, per-chunk charging, completion, usage recording and account-page export share the production on-disk SQLite connection (WAL, normal production synchronous setting). Accounts are seeded before the idle baseline. These are not 1,000 tunnels on one account. All per-owner and bandwidth limits remain enabled. Login and authenticated account rendering use the production handlers; the probed account owns the first traffic tunnel. Account probes reject unavailable usage, and successful visitors require a metering request ID. Per-step registration shape and the first owner’s cumulative ledger export are retained in capacity.json. External OAuth/email delivery, remote networks and HTTP/3 are excluded. No product limits or deployment configuration are changed.", "",
             "Failure criteria declared before the run: RSS above the budget; incomplete publisher registration; visitor error rate above 1%; or scheduled-arrival full-body p99 above 500 ms. Login and authenticated account probes arrive independently at five requests/second each, including during overload. Page responsiveness requires zero errors and p99 at most 1,000 ms. A dispatcher p99 lag above 100 ms invalidates a traffic step as generator-limited. Percentiles use nearest rank and include errors/timeouts as attempt durations. Timed-out full-body completion latencies are right-censored at the recorded deadline, not successful completions; traffic latency includes scheduling lag, avoiding completion-paced coordinated omission. An idle step has no visitor requests, so its p99 and error rate are N/A. RSS is process-only, sampled every 50 ms (shorter peaks may be missed); CPU is process CPU seconds divided by step wall time.", "",
             "| Stage | Publishers / RPS | RSS peak MiB | Attempt p99 ms | Error % | Completed RPS | Relay CPU cores | Login p99 ms / errors | Account p99 ms / errors | Result |",
             "|---|---:|---:|---:|---:|---:|---:|---|---|---|"]
    for row in data['steps']:
        load = row.get('load', {})
        traffic = load.get('traffic', {})
        page = lambda name: (f"{load[name]['p99_ms']:.2f} / {load[name]['errors']}" if name in load else "N/A")
        lines.append(f"| {row['stage']} | {row['target']} | {row['rss_peak_mib']:.2f} | " +
                     (f"{traffic['p99_ms']:.2f} | {100*traffic['error_rate']:.3f}" if traffic else "N/A | N/A") +
                     f" | {load.get('completed_rps', 0):.2f} | {row['cpu_cores']:.2f} | {page('login')} | {page('account')} | {row['failure'] or ('functional pass; timing warning: '+row['timing_warning'] if row.get('timing_warning') else 'pass')} |")
    idle = [r for r in data['steps'] if r['stage'] == 'idle' and not r['failure']]
    memory = "not enough successful idle steps to estimate"
    if len(idle) >= 2:
        low, high = idle[0], idle[-1]
        slope = (high['rss_end_mib'] - low['rss_end_mib']) * 1024 / (high['target'] - low['target'])
        memory = f"{slope:.2f} KiB per additional idle tunnel ({low['target']}→{high['target']}, ending RSS {low['rss_end_mib']:.2f}→{high['rss_end_mib']:.2f} MiB). This endpoint slope includes gRPC/TLS connections, maps, allocator retention and GC; it is not a constant heap allocation."
    lines += ["", "Memory per idle tunnel: " + memory, "", "First failure: " + (json.dumps(data['first_failure']) if data['first_failure'] else "none observed through the requested ramp; the breaking point is above this tested envelope, not measured here."), "",
              "Machine/provenance and exact invocation:", "", "```json", json.dumps({k: v for k, v in data.items() if k != 'steps'}, indent=2), "```", "",
              "Per-step summaries are in capacity.json; compressed individual visitor observations are in traffic-*.json.gz under artifact_directory (recorded above). Driver source, overlay, build log, readiness handshakes and child logs are retained with the evidence. Failed HTTP status, body length and deadlines remain errors; no successful latency is substituted.", ""]
    good = [r for r in data['steps'] if r['stage'] == 'traffic' and not r['failure'] and r['pages_responsive']]
    bad = [r for r in data['steps'] if r['stage'] == 'traffic' and not r['pages_responsive']]
    failed = [r for r in data['steps'] if r['stage'] == 'traffic' and r['failure']]
    if failed:
        first = failed[0]
        lines += [f"Failure mode at {first['target']} offered RPS: {first['failure']}; relay CPU {first['cpu_cores']:.2f} core(s), peak RSS {first['rss_peak_mib']:.2f} MiB versus {data['rss_budget_mib']} MiB budget. " + ("RSS stayed below budget and the relay remained alive: no OOM was observed. Latency/deadline failures are consistent with request or ledger queueing; this experiment does not isolate CPU scheduling from SQLite contention or storage latency." if first['rss_peak_mib'] < data['rss_budget_mib'] else "RSS reached the budget."), ""]
    lines += ["Login and account pages: " + (f"responsive at all {len(good)} passing traffic steps; " if good else "no fully passing traffic step; ") + (f"not responsive at {', '.join(str(r['target']) for r in bad)} offered RPS." if bad else "no page responsiveness failure observed during the traffic ramp."), ""]
    if data["self_test"]:
        lines.append("Recommendation: use the full capacity stage for sizing; this tiny ramp checks HTTP correctness and failure reporting only. Timing spikes remain visible as warnings; HTTP, body and process failures still fail the self-test.")
    elif good:
        best = max([r for r in good if r['cpu_cores'] <= .8 * data['cpus']] or good, key=lambda r: r['target'])
        lines.append(f"Recommendation: stay at this size for this measured workload up to {best['target']} offered RPS on {data['traffic_tunnels']} tunnels (p99 {best['load']['traffic']['p99_ms']:.2f} ms, peak RSS {best['rss_peak_mib']:.2f} MiB, {data['rss_budget_mib']-best['rss_peak_mib']:.2f} MiB RSS headroom, {100*max(0, 1-best['cpu_cores']/data['cpus']):.1f}% measured CPU headroom). Treat the first failing step as outside the supported envelope; no larger machine's headroom is claimed without measurement.")
    else:
        lines.append("Recommendation: this size has no demonstrated passing traffic envelope in this run; do not infer a CPU or memory upgrade's headroom without measuring it.")
    (output / 'CAPACITY.md').write_text('\n'.join(lines) + '\n')


def capacity(args, repo, work, output, start):
    if not sys.platform.startswith('linux'):
        raise RuntimeError('capacity requires Linux taskset and /proc')
    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < args.capacity_cpus + 1:
        raise RuntimeError('capacity requires separate allowed CPU(s) for the load generator')
    relay_cpus = cpus[:args.capacity_cpus]
    other_cpus = cpus[args.capacity_cpus:]
    source = Path(__file__).with_name('capacity-driver.go.txt')
    (work / 'capacity-driver.go').write_bytes(source.read_bytes())
    overlay = {'Replace': {str(repo / 'internal/host/relay_capacity_generated_test.go'): str(work / 'capacity-driver.go')}}
    (work / 'overlay.json').write_text(json.dumps(overlay))
    binary = work / 'relay-capacity.test'
    env = {k: v for k, v in os.environ.items() if not k.startswith(('TUNN_', 'RC_', 'RB_'))}
    (work / 'tmp').mkdir(exist_ok=True)
    env.update(TMPDIR=str(work / 'tmp'), GOTMPDIR=str(work / 'tmp'), RC_WORK=str(work), RC_BODY=str(args.capacity_body), GOMAXPROCS='4')
    with (work / 'build.log').open('w') as log:
        subprocess.run(['go', 'test', '-p', '2', '-overlay', str(work / 'overlay.json'), '-c', '-o', str(binary), './internal/host'], cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=300)
    data = {'version': 1, 'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
            'cpus': args.capacity_cpus, 'relay_affinity': relay_cpus, 'other_affinity': other_cpus,
            'gomemlimit': args.capacity_gomemlimit, 'rss_budget_mib': args.capacity_rss_mib,
            'body_bytes': args.capacity_body, 'traffic_tunnels': 2 if args.capacity_self_test else 20,
            'step_seconds': 1 if args.capacity_self_test else args.capacity_seconds,
            'machine': {'hostname': platform.node(), 'platform': platform.platform(), 'cpu': next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'), 'go': subprocess.check_output(['go', 'version'], text=True).strip(), 'loadavg': Path('/proc/loadavg').read_text().strip()},
            'niceness': os.getpriority(os.PRIO_PROCESS, 0), 'command': shlex.join(['nice', '-n', '10', sys.executable, *sys.argv]), 'artifact_directory': str(output), 'steps': [], 'first_failure': None,
            'self_test': args.capacity_self_test, 'forced_failure': args.capacity_force_failure}
    children, logs = [], []
    stopped = threading.Event()
    memory_exceeded = threading.Event()
    rss_samples = []
    ticks = os.sysconf('SC_CLK_TCK')

    def process_stats(pid):
        status = Path(f'/proc/{pid}/status').read_text()
        rss = next((int(line.split()[1]) / 1024 for line in status.splitlines() if line.startswith('VmRSS:')), 0)
        stat = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return rss, (int(stat[11]) + int(stat[12])) / ticks

    def launch(role, affinity, extra=None):
        child_env = dict(env, RC_ROLE=role, **(extra or {}))
        path = output / f'{role}-{len(children)}.log'
        log = path.open('w'); logs.append(log)
        child = subprocess.Popen(['taskset', '-c', ','.join(map(str, affinity)), str(binary), '-test.run=^TestRelayCapacityDriver$', '-test.v', '-test.timeout=40m'], cwd=repo, env=child_env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        children.append(child)
        return child

    def ready(name, process):
        path = work / f'{name}-ready.json'
        # Each run gets a new work directory; never accept an old handshake.
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f'{name} exited {process.returncode}; see child log')
            if path.exists():
                try:
                    return json.loads(path.read_text())
                except json.JSONDecodeError:
                    pass
            time.sleep(.05)
        raise RuntimeError(f'{name} startup timeout')

    def get(url):
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.read()

    def record(row):
        if row['failure'] and data['first_failure'] is None:
            data['first_failure'] = {'stage': row['stage'], 'target': row['target'], 'mode': row['failure']}
        data['steps'].append(row)
        print(json.dumps({k:v for k,v in row.items() if k != 'load'}), flush=True)
        (output / 'capacity.json').write_text(json.dumps(data, indent=2) + '\n')

    try:
        relay = launch('relay', relay_cpus, {'RC_OWNERS': '6' if args.capacity_self_test else '1000', 'GOMEMLIMIT': args.capacity_gomemlimit, 'GOMAXPROCS': str(args.capacity_cpus)})
        relay_ready = ready('relay', relay)
        data['database'] = {k: relay_ready[k] for k in ('journal_mode', 'synchronous', 'owners')}
        if data['database']['journal_mode'] != 'wal':
            raise RuntimeError('production WAL database required')
        data['relay_pid'] = relay.pid
        data['relay_affinity_observed'] = sorted(os.sched_getaffinity(relay.pid))
        data['relay_niceness'] = os.getpriority(os.PRIO_PROCESS, relay.pid)
        if data['relay_affinity_observed'] != relay_cpus:
            raise RuntimeError('taskset affinity did not take effect')

        def monitor():
            while not stopped.is_set():
                try:
                    rss, _ = process_stats(relay.pid)
                    rss_samples.append(rss)
                    if rss > args.capacity_rss_mib:
                        memory_exceeded.set(); relay.terminate(); return
                except (OSError, ValueError):
                    return
                stopped.wait(.05)
        watcher = threading.Thread(target=monitor, daemon=True); watcher.start()
        publishers = launch('publishers', other_cpus, {'RC_GRPC': relay_ready['grpc'], 'RC_BROKEN': '1' if args.capacity_force_failure else '0'})
        pub_ready = ready('publishers', publishers)

        def set_tunnels(n):
            get(pub_ready['admin'] + f'/?n={n}')
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if relay.poll() is not None:
                    raise RuntimeError('RSS budget exceeded' if memory_exceeded.is_set() else 'relay exited')
                state = json.loads(get(relay_ready['admin']))
                if state['tunnels'] == n:
                    if not (state['account_backed'] == n and state['quota_exempt'] == 0 and state['shared'] == n and state['metering'] and state['account_plans']):
                        raise RuntimeError(f'production account/metering shape missing: {state}')
                    return state
                time.sleep(.1)
            raise RuntimeError(f'publisher registration failed to reach {n}')

        for n in ([2, 6] if args.capacity_self_test else [10, 50, 100, 200, 400, 600, 800, 1000]):
            at = len(rss_samples); before = process_stats(relay.pid)[1]; begin = time.monotonic()
            failure, state = None, None
            try:
                state = set_tunnels(n); time.sleep(.1 if args.capacity_self_test else 3)
            except (OSError, RuntimeError) as exc:
                failure = str(exc)
            rss, cpu = process_stats(relay.pid) if relay.poll() is None else (0, before)
            record({'stage': 'idle', 'target': n, 'registration': state, 'rss_peak_mib': max(rss_samples[at:] or [rss]), 'rss_end_mib': rss, 'cpu_cores': (cpu-before)/(time.monotonic()-begin), 'failure': failure})
            if failure:
                break
        if relay.poll() is None and not data['first_failure']:
            traffic_registration = set_tunnels(data['traffic_tunnels'])
            time.sleep(.1 if args.capacity_self_test else 3)
            for rate in ([2, 5] if args.capacity_self_test else [10, 50, 100, 200, 400, 600, 800, 1000, 1250, 1500, 2000]):
                if rate > 1000 and data['first_failure']:
                    break
                at = len(rss_samples); before = process_stats(relay.pid)[1]; begin = time.monotonic()
                child = launch('load', other_cpus, {'RC_INGRESS': relay_ready['ingress'], 'RC_COOKIE': relay_ready['cookie'], 'RC_RPS': str(rate), 'RC_SECONDS': str(data['step_seconds']), 'RC_TUNNELS': str(data['traffic_tunnels'])})
                code = child.wait(timeout=data['step_seconds'] + 30)
                if code or relay.poll() is not None:
                    raise RuntimeError('RSS budget exceeded' if memory_exceeded.is_set() else f'load process failed: {code}')
                load = json.loads((work / 'load-result.json').read_text())
                with gzip.open(output / f'traffic-{rate}.json.gz', 'wt') as compressed:
                    json.dump(load.pop('samples'), compressed)
                usage = json.loads(get(relay_ready['admin'] + '/usage'))
                traffic = load['traffic']
                failure = ('generator queueing (invalid measurement)' if traffic.get('generator_errors', 0) or traffic['dispatch_lag_p99_ms'] > 100 else
                           'errors' if traffic['error_rate'] > .01 else 'queueing' if traffic['p99_ms'] > 500 else None)
                pages_responsive = all(load[k]['errors'] == 0 and load[k]['p99_ms'] <= 1000 for k in ('login', 'account'))
                if not pages_responsive and failure is None:
                    failure = 'control-plane errors or queueing'
                timing_warning = None
                if args.capacity_self_test:
                    # A one-second fragment proves HTTP correctness, not a stable
                    # capacity percentile on a shared host. Keep timing visible.
                    errors = traffic['errors'] + sum(load[k]['errors'] for k in ('login', 'account'))
                    timing_warning = failure if not errors else None
                    failure = 'errors' if errors else None
                rss, cpu = process_stats(relay.pid)
                record({'stage': 'traffic', 'target': rate, 'registration': traffic_registration, 'ledger_export': usage, 'rss_peak_mib': max(rss_samples[at:] or [rss]), 'rss_end_mib': rss, 'cpu_cores': (cpu-before)/(time.monotonic()-begin), 'load': load,
                        'pages_responsive': pages_responsive, 'timing_warning': timing_warning, 'failure': failure})
        if args.capacity_force_failure and data['first_failure'] is None:
            raise RuntimeError('forced failure was not detected')
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        data['harness_error'] = str(exc)
        if data['first_failure'] is None:
            data['first_failure'] = {'stage': 'harness', 'mode': str(exc)}
    finally:
        stopped.set()
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait()
        for log in logs:
            log.close()
    for name in ('capacity-driver.go', 'overlay.json', 'build.log', 'relay-ready.json', 'publishers-ready.json'):
        if (work / name).exists():
            shutil.copyfile(work / name, output / name)
    data['elapsed_seconds'] = time.monotonic() - start
    if data['elapsed_seconds'] >= 2700:
        data['harness_error'] = 'exceeded 45 minute runtime budget'
    (output / 'capacity.json').write_text(json.dumps(data, indent=2) + '\n')
    capacity_report(data, output)
    print(f"Wrote {output / 'CAPACITY.md'} in {data['elapsed_seconds']:.1f}s; first failure: {data['first_failure']}", flush=True)
    return int(bool(data.get('harness_error')) or any('generator' in (r['failure'] or '') for r in data['steps']) or args.capacity_force_failure or (args.capacity_self_test and bool(data['first_failure'])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True, help="scratch directory outside checkout")
    parser.add_argument("--output", type=Path, required=True, help="evidence directory outside checkout")
    parser.add_argument("--self-test-broken-origin", action="store_true")
    parser.add_argument("--capacity", action="store_true", help="bounded single-relay capacity stage; no frp download")
    parser.add_argument("--capacity-self-test", action="store_true", help="tiny six-publisher idle ramp and two-tunnel traffic ramp")
    parser.add_argument("--capacity-force-failure", action="store_true", help="truncated origin; must report failure and exit nonzero")
    parser.add_argument("--capacity-cpus", type=int, choices=(1, 2), default=1)
    parser.add_argument("--capacity-gomemlimit", default="400MiB")
    parser.add_argument("--capacity-rss-mib", type=int, default=512)
    parser.add_argument("--capacity-body", type=int, default=256*1024)
    parser.add_argument("--capacity-seconds", type=int, default=15)
    args = parser.parse_args()
    if args.capacity and args.self_test_broken_origin:
        parser.error("use --capacity-force-failure for capacity")
    if not (1 <= args.capacity_seconds <= 60 and 1 <= args.capacity_body <= 1048576 and 64 <= args.capacity_rss_mib <= 1024):
        parser.error("capacity requires 1..60 seconds, 1..1048576 body bytes, and 64..1024 MiB RSS budget")
    if (args.capacity_self_test or args.capacity_force_failure) and not args.capacity:
        parser.error("capacity test switches require --capacity")
    start = time.monotonic()
    if os.getpriority(os.PRIO_PROCESS, 0) < 10:
        os.nice(10 - os.getpriority(os.PRIO_PROCESS, 0))
    repo = Path(__file__).resolve().parents[2]
    work, output = args.work_dir.resolve(), args.output.resolve()
    for path in (work, output):
        if path == repo or repo in path.parents:
            parser.error("work and evidence directories must be outside the checkout")
        path.mkdir(parents=True, exist_ok=True)
    if args.capacity:
        # Refuse stale ready files or overwriting a measurement; use a fresh path.
        if (work / 'relay-ready.json').exists() or (output / 'capacity.json').exists():
            parser.error("capacity work/output already used; choose fresh directories")
        return capacity(args, repo, work, output, start)
    (work / "driver_test.go").write_text(DRIVER)
    overlay = {"Replace": {str(repo / "internal/host/relay_bench_generated_test.go"): str(work / "driver_test.go")}}
    (work / "overlay.json").write_text(json.dumps(overlay))
    binary = work / "relay-bench.test"
    with (work / "build.log").open("w") as log:
        subprocess.run(["go", "test", "-p", "2", "-overlay", str(work / "overlay.json"), "-c", "-o", str(binary), "./internal/host"], cwd=repo, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=300)
    env = os.environ.copy()
    # Ambient developer/production credentials must never enter the fixture.
    env = {k: v for k, v in env.items() if not k.startswith("TUNN_")}
    env.update(RB_WORK=str(work), RB_RAW=str(output / "raw.json"))
    if args.self_test_broken_origin:
        env["RB_BROKEN"] = "1"
    else:
        env["RB_FRP"] = str(release(work))
    command = [str(binary), "-test.run=^TestRelayBenchDriver$", "-test.v", "-test.timeout=28m"]
    with (work / ("self-test.log" if args.self_test_broken_origin else "driver.log")).open("w") as log:
        result = subprocess.run(command, cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=max(1, 1740 - (time.monotonic() - start)))
    if result.returncode:
        print(log.name + ":\n" + Path(log.name).read_text()[-6000:], file=sys.stderr)
        return result.returncode
    if args.self_test_broken_origin:
        raise RuntimeError("broken origin unexpectedly succeeded")
    elapsed = time.monotonic() - start
    if elapsed >= 1800:
        raise RuntimeError("benchmark exceeded 30 minute budget")
    data = {"version": 1, "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
            "machine": {"hostname": platform.node(), "platform": platform.platform(), "cpu": next((line.split(":", 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), "unknown"), "logical_cpus": os.cpu_count(), "affinity_cpus": len(os.sched_getaffinity(0)), "go": subprocess.check_output(["go", "version"], text=True).strip(), "meminfo": Path('/proc/meminfo').read_text().splitlines()[:3], "loadavg": Path('/proc/loadavg').read_text().strip()},
            "elapsed_seconds": elapsed, "niceness": os.getpriority(os.PRIO_PROCESS, 0),
            "command": f"nice -n 10 make bench-relay BENCH_ARGS='--work-dir {work} --output {output}'",
            "self_test_command": f"nice -n 10 python3 scripts/bench/relay-bench.py --work-dir {work} --output {output} --self-test-broken-origin",
            "frp": {"version": FRP_VERSION, "url": FRP_URL, "sha256": FRP_SHA256},
            "runs": json.loads((output / "raw.json").read_text())}
    (output / "bench.json").write_text(json.dumps(data, indent=2) + "\n")
    report(data, output)
    print(f"Wrote {output / 'bench.json'} and {output / 'BENCH.md'} in {elapsed:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"relay-bench: {exc}", file=sys.stderr)
        sys.exit(1)
