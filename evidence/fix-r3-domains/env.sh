mkdir -p .scratch/go-path .scratch/go-cache .scratch/tmp
export GOMAXPROCS=4 GOFLAGS='-p=4' GOTOOLCHAIN=local GOENV=off GOTELEMETRY=off
export GOPATH="$PWD/.scratch/go-path" GOMODCACHE=/work/cache/go/mod GOCACHE="$PWD/.scratch/go-cache"
export TMPDIR="$PWD/.scratch/tmp" GOTMPDIR="$PWD/.scratch/tmp"
export PYTHONDONTWRITEBYTECODE=1
umask 022

export GOCACHEPROG="python3 $PWD/evidence/fix-r3-domains/cache-fallback.py" GOPROXY=off GOSUMDB=off
