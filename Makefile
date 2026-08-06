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

# Safety: delete partial outputs on error
.DELETE_ON_ERROR:

.PHONY: all build test test-short test-coverage clean fmt vet lint deps help

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

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out coverage.html

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
