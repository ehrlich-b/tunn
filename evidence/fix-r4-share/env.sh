mkdir -p .scratch/go-path .scratch/go-cache .scratch/tmp
export GOMAXPROCS=4 GOFLAGS='-p=4' GOTOOLCHAIN=local GOENV=off GOTELEMETRY=off
export GOPATH="$PWD/.scratch/go-path" GOMODCACHE=/work/cache/go/mod GOCACHE="$PWD/.scratch/go-cache"
export TMPDIR="$PWD/.scratch/tmp" GOTMPDIR="$PWD/.scratch/tmp"
export GOPROXY=off GOSUMDB=off PYTHONDONTWRITEBYTECODE=1
unset GOCACHEPROG
export PLAYWRIGHT_BROWSERS_PATH=/home/ehrlich/.cache/ms-playwright
export TUNN_SHARE_BROWSER_PYTHON=/work/lanes/tunn-share/review/.venv/bin/python
umask 022
