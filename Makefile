# Makefile for trajan

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "0.1.0")
GIT_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildDate=$(BUILD_DATE)

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
WASM_EXEC := $(shell test -f "$$(go env GOROOT)/lib/wasm/wasm_exec.js" && echo "$$(go env GOROOT)/lib/wasm/wasm_exec.js" || echo "$$(go env GOROOT)/misc/wasm/wasm_exec.js")
WASM_LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_DATE)

# Safety: delete partial outputs on error
.DELETE_ON_ERROR:

.PHONY: all build test test-short test-coverage clean fmt vet lint deps help wasm wasm-dist wasm-serve wasm-smoke

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

## wasm: Compile Go to WASM and refresh browser assets
wasm:
	@mkdir -p $(WASM_DIR)
	@echo "Compiling Go to WASM..."
	GOWORK=off GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags "$(WASM_LDFLAGS)" -o $(WASM_DIR)/trajan.wasm ./$(WASM_SRC)
	@echo "WASM binary: $$(du -h $(WASM_DIR)/trajan.wasm | cut -f1)"
	@test -f "$(WASM_EXEC)" || (echo "Error: wasm_exec.js not found at $(WASM_EXEC)" && exit 1)
	cp -f "$(WASM_EXEC)" $(WASM_DIR)/wasm_exec.js
	cp -f internal/report/assets/report.css $(WASM_DIR)/report.css

## wasm-dist: Build standalone single-file HTML
wasm-dist: wasm
	@echo "Building standalone distribution..."
	@cd $(WASM_DIR) && python3 -c "\
	import base64, os; \
	html = open('index.html').read(); \
	report_css = open('report.css').read(); \
	shell_css = open('shell.css').read(); \
	css = report_css + '\n' + shell_css; \
	wasmjs = open('wasm_exec.js').read(); \
	fsshim = open('fs-shim.js').read(); \
	bridgejs = open('bridge.js').read(); \
	appjs = open('app.js').read(); \
	wasm = base64.b64encode(open('trajan.wasm','rb').read()).decode(); \
	html = html.replace('<link rel=\"stylesheet\" href=\"report.css\">\n<link rel=\"stylesheet\" href=\"shell.css\">', '<style>' + css + '</style>'); \
	html = html.replace('<script src=\"fs-shim.js\"></script>', '<script>' + fsshim + '</script>'); \
	html = html.replace('<script src=\"wasm_exec.js\"></script>', '<script>' + wasmjs + '</script>'); \
	html = html.replace('<script src=\"bridge.js\"></script>', '<script>' + bridgejs + '</script>'); \
	html = html.replace('<script src=\"app.js\"></script>', '<script>function _wasmDataUrl(){return \"data:application/wasm;base64,' + wasm + '\";}</script><script>' + appjs + '</script>'); \
	open('trajan-standalone.html','w').write(html); \
	print(f'Standalone: {os.path.getsize(\"trajan-standalone.html\") / 1048576:.1f}MB')"
	@echo "Output: $(WASM_DIR)/trajan-standalone.html"

## wasm-serve: Start local WASM dev server
wasm-serve: wasm
	@echo "Starting dev server at http://localhost:8080"
	@cd $(WASM_DIR) && $(GO) run server.go

## wasm-smoke: Exercise fs shim + WASM init + fixture scan/report
wasm-smoke: wasm
	node $(WASM_DIR)/smoke-fs.mjs
	node $(WASM_DIR)/smoke-wasm.mjs
	node $(WASM_DIR)/smoke-pipeline.mjs

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
	golangci-lint run --max-same-issues 0 --max-issues-per-linter 0 ./...

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
