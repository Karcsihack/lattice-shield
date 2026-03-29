BINARY     := lattice-shield
MODULE     := github.com/lattice-suite/lattice-shield
VERSION    := 1.0.0
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS    := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -s -w"

.PHONY: all build clean test lint install tidy

all: tidy build

## build: Compile the binary for the current OS/arch
build:
	go build $(LDFLAGS) -o $(BINARY) .

## install: Install binary to GOPATH/bin
install:
	go install $(LDFLAGS) .

## tidy: Download and tidy Go modules
tidy:
	go mod tidy

## test: Run the full test suite
test:
	go test ./... -race -count=1

## test-cover: Run tests and generate an HTML coverage report
test-cover:
	go test ./... -race -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run staticcheck (install: go install honnef.co/go/tools/cmd/staticcheck@latest)
lint:
	staticcheck ./...

## build-all: Cross-compile for Linux, macOS, Windows
build-all:
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64   .
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64  .
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64  .
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe .

## clean: Remove build artifacts
clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist/ coverage.out coverage.html

## demo: Run a quick self-scan to show Lattice-Shield in action
demo:
	@echo "--- Scanning scanner/patterns.go (should be clean) ---"
	./$(BINARY) scan scanner/patterns.go
	@echo "--- Anonymize dry-run on anonymizer/anonymizer.go ---"
	./$(BINARY) anonymize --dry-run anonymizer/anonymizer.go

help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
