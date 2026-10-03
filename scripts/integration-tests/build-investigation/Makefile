# Invoke from the repository root: make -f scripts/integration-tests/build-investigation/Makefile test
.PHONY: build test serve investigate setup-python python-investigate test-relay fmt
build:
	go build -o ./bin/build-investigation ./scripts/integration-tests/build-investigation

test:
	go test -race -count=1 -timeout=30s ./internal/builddemo ./scripts/integration-tests/build-investigation

serve: build
	./bin/build-investigation serve $(ARGS)

investigate: build
	./bin/build-investigation investigate $(ARGS)

setup-python:
	UV_CACHE_DIR="$(CURDIR)/.cache/uv" uv venv scripts/integration-tests/build-investigation/.venv --python python3
	UV_CACHE_DIR="$(CURDIR)/.cache/uv" uv pip install --python scripts/integration-tests/build-investigation/.venv/bin/python -r scripts/integration-tests/build-investigation/requirements.lock

python-investigate:
	scripts/integration-tests/build-investigation/.venv/bin/python scripts/integration-tests/build-investigation/client.py $(ARGS)

test-relay:
	TUNN_PYTHON="$(CURDIR)/scripts/integration-tests/build-investigation/.venv/bin/python" go test -race -count=1 -timeout=60s -v -run '^TestGrantTwoSDKBuildWorkflowAcrossRealRelay$$' ./internal/host

fmt:
	gofmt -w internal/builddemo/*.go scripts/integration-tests/build-investigation/*.go internal/host/grant_workflow_integration_test.go
