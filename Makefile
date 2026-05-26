# Makefile for trajan

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "0.1.0")
GIT_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildDate=$(BUILD_DATE)

GOLANGCI_LINT_VERSION ?= v2.12.2

# Go commands
GO := go
GOFMT := gofmt
GOTEST := $(GO) test
GOBUILD := CGO_ENABLED=0 $(GO) build

# Directories
BIN_DIR := bin
CMD_DIR := cmd/trajan
WASM_DIR := browser
WASM_SRC := cmd/trajan-wasm

# WASM build
GOROOT_DIR := $(shell go env GOROOT)
WASM_EXEC := $(shell test -f "$$(go env GOROOT)/lib/wasm/wasm_exec.js" && echo "$$(go env GOROOT)/lib/wasm/wasm_exec.js" || echo "$$(go env GOROOT)/misc/wasm/wasm_exec.js")
WASM_LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_DATE)

# Safety: delete partial outputs on error
.DELETE_ON_ERROR:

.PHONY: all build test test-short test-coverage clean fmt vet lint deps help version wasm wasm-dist wasm-serve jenkins-test-up jenkins-test-down jenkins-integration

all: build

## build: Build the trajan binary
build:
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/trajan ./$(CMD_DIR)

## test: Run all tests
test:
	$(GOTEST) -v -race ./...

## test-short: Run tests in short mode (for CI)
test-short:
	$(GOTEST) -short ./...

## test-coverage: Run tests with coverage
test-coverage:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

## wasm: Compile Go to WASM and copy wasm_exec.js
wasm:
	@echo "Compiling Go to WASM..."
	GOWORK=off GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags "$(WASM_LDFLAGS)" -o $(WASM_DIR)/trajan.wasm ./$(WASM_SRC)
	@echo "WASM binary: $$(du -h $(WASM_DIR)/trajan.wasm | cut -f1)"
	@test -f "$(WASM_EXEC)" || (echo "Error: wasm_exec.js not found at $(WASM_EXEC)" && exit 1)
	cp -f "$(WASM_EXEC)" $(WASM_DIR)/wasm_exec.js

## wasm-dist: Build standalone single-file HTML for deployment
wasm-dist: wasm
	@echo "Building standalone distribution..."
	@cd $(WASM_DIR) && python3 -c "\
	import base64, os; \
	html = open('index.html').read(); \
	css = open('styles.css').read(); \
	wasmjs = open('wasm_exec.js').read(); \
	bridgejs = open('bridge.js').read(); \
	appjs = open('app.js').read(); \
	wasm = base64.b64encode(open('trajan.wasm','rb').read()).decode(); \
	bridgejs = bridgejs.replace(\"fetch('trajan.wasm')\", 'fetch(_wasmDataUrl())'); \
	html = html.replace('<link rel=\"stylesheet\" href=\"styles.css\">', '<style>' + css + '</style>'); \
	html = html.replace('<script src=\"wasm_exec.js\"></script>', '<script>' + wasmjs + '</script>'); \
	html = html.replace('<script src=\"bridge.js\"></script>', '<script>' + bridgejs + '</script>'); \
	html = html.replace('<script src=\"app.js\"></script>', '<script>function _wasmDataUrl(){return \"data:application/wasm;base64,' + wasm + '\";}\n' + appjs + '</script>'); \
	open('trajan-standalone.html','w').write(html); \
	print(f'Standalone: {os.path.getsize(\"trajan-standalone.html\") / 1048576:.1f}MB')"
	@echo "Output: $(WASM_DIR)/trajan-standalone.html"

## wasm-serve: Start local WASM dev server
wasm-serve: wasm
	@echo "Starting dev server at http://localhost:8080"
	@cd $(WASM_DIR) && $(GO) run server.go

## version: Calculate next semantic version from git tags and commit message
version:
	@tag=$$(git tag -l 'v*' --sort=-v:refname | head -n1); \
	if [ -z "$$tag" ]; then latest="0.0.0"; else latest=$$(echo "$$tag" | sed 's/^v//'); fi; \
	msg=$$(git log -1 --format=%s); \
	major=$$(echo "$$latest" | cut -d. -f1); \
	minor=$$(echo "$$latest" | cut -d. -f2); \
	patch=$$(echo "$$latest" | cut -d. -f3); \
	if echo "$$msg" | grep -q '\[major-release\]'; then \
		major=$$((major + 1)); minor=0; patch=0; \
	elif echo "$$msg" | grep -q '\[minor-release\]'; then \
		minor=$$((minor + 1)); patch=0; \
	else \
		patch=$$((patch + 1)); \
	fi; \
	echo "v$$major.$$minor.$$patch"

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html
	rm -f $(WASM_DIR)/trajan.wasm $(WASM_DIR)/wasm_exec.js $(WASM_DIR)/trajan-standalone.html

## fmt: Format Go code
fmt:
	$(GOFMT) -s -w .

## vet: Run go vet
vet:
	$(GO) vet ./...

## lint: Run linters
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found, running via go run $(GOLANGCI_LINT_VERSION)..."; \
		go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...; \
	fi

## deps: Download dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'

## jenkins-test-up: Start Jenkins test instance
jenkins-test-up:
	docker compose -f test/jenkins/docker-compose.yml up -d
	@echo "Waiting for Jenkins to be healthy..."
	@until docker compose -f test/jenkins/docker-compose.yml exec -T jenkins curl -sf http://localhost:8080/login > /dev/null 2>&1; do sleep 5; done
	@echo "Jenkins is ready at http://localhost:18080"

## jenkins-test-down: Stop Jenkins test instance
jenkins-test-down:
	docker compose -f test/jenkins/docker-compose.yml down -v

## jenkins-integration: Run Jenkins integration tests
jenkins-integration: build
	JENKINS_TEST_URL=http://localhost:18080 JENKINS_TEST_USER=admin JENKINS_TEST_TOKEN=admin \
		$(GOTEST) -v -tags integration ./pkg/jenkins/... ./cmd/trajan/jenkins/...
