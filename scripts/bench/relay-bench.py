#!/usr/bin/env python3
"""Bounded loopback relay comparison. Python 3 + Go; no installed dependencies.

make bench-relay BENCH_ARGS='--work-dir /absolute/scratch --output /absolute/evidence'
The Go driver is compiled through an overlay: the checkout is never modified.
--self-test-broken-origin deliberately returns nonzero on a truncated 1 KiB body.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tarfile
import time
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True, help="scratch directory outside checkout")
    parser.add_argument("--output", type=Path, required=True, help="evidence directory outside checkout")
    parser.add_argument("--self-test-broken-origin", action="store_true")
    args = parser.parse_args()
    start = time.monotonic()
    if os.getpriority(os.PRIO_PROCESS, 0) < 10:
        os.nice(10 - os.getpriority(os.PRIO_PROCESS, 0))
    repo = Path(__file__).resolve().parents[2]
    work, output = args.work_dir.resolve(), args.output.resolve()
    for path in (work, output):
        if path == repo or repo in path.parents:
            parser.error("work and evidence directories must be outside the checkout")
        path.mkdir(parents=True, exist_ok=True)
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
