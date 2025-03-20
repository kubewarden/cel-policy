# Binary directory
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
BIN_DIR := $(abspath $(ROOT_DIR)/bin)

SOURCE_FILES := $(shell find . -type f -name '*.go')
VERSION ?= $(shell git describe | cut -c2-)

GOLANGCI_LINT_VER := v1.64.5
GOLANGCI_LINT_BIN := golangci-lint
GOLANGCI_LINT := $(BIN_DIR)/$(GOLANGCI_LINT_BIN)


policy.wasm: $(SOURCE_FILES) go.mod go.sum
	GOOS=wasip1 GOARCH=wasm go build -gcflags=all="-l -B -wb=false" -ldflags="-w -s" -o policy.wasm
	wasm-opt --enable-bulk-memory -Oz -o policy.wasm policy.wasm 


annotated-policy.wasm: policy.wasm metadata.yml
	kwctl annotate -m metadata.yml -u README.md -o annotated-policy.wasm policy.wasm

golangci-lint: $(GOLANGCI_LINT) ## Install a local copy of golang ci-lint.
$(GOLANGCI_LINT): ## Install golangci-lint.
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VER)

.PHONY: lint
lint: $(GOLANGCI_LINT)
	go vet ./...
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run --fix

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: clean
clean:
	go clean
	rm -f policy.wasm annotated-policy.wasm

.PHONY: e2e-tests
e2e-tests: annotated-policy.wasm
	bats e2e.bats
