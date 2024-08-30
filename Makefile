# Binary directory
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
BIN_DIR := $(abspath $(ROOT_DIR)/bin)

SOURCE_FILES := $(shell find . -type f -name '*.go')
VERSION ?= $(shell git describe | cut -c2-)

GOLANGCI_LINT_VER := v1.60.1
GOLANGCI_LINT_BIN := golangci-lint
GOLANGCI_LINT := $(BIN_DIR)/$(GOLANGCI_LINT_BIN)
WASM_OPT_BIN := wasm-opt
WASM_OPT := $(BIN_DIR)/$(WASM_OPT_BIN)


policy.wasm: $(SOURCE_FILES) go.mod go.sum $(WASM_OPT)
	GOOS=wasip1 GOARCH=wasm go build -gcflags=all="-l -B -wb=false" -ldflags="-w -s" -o policy.wasm
	$(WASM_OPT) --enable-bulk-memory -Oz -o policy.wasm policy.wasm 

$(BIN_DIR): 
	mkdir -p $(BIN_DIR)

$(WASM_OPT): $(BIN_DIR) ## Install wasm-opt
	curl -XGET -L -o /tmp/binaryen.tar.gz https://github.com/WebAssembly/binaryen/releases/download/version_118/binaryen-version_118-x86_64-linux.tar.gz
	tar -xf /tmp/binaryen.tar.gz -C /tmp
	mv /tmp/binaryen-version_118/bin/wasm-opt $(WASM_OPT)
	touch $(WASM_OPT)


artifacthub-pkg.yml: metadata.yml go.mod
	$(warning If you are updating the artifacthub-pkg.yml file for a release, \
	  remember to set the VERSION variable with the proper value. \
	  To use the latest tag, use the following command:  \
	  make VERSION=$$(git describe --tags --abbrev=0 | cut -c2-) annotated-policy.wasm)
	kwctl scaffold artifacthub \
	  --metadata-path metadata.yml --version $(VERSION) \
	  --output artifacthub-pkg.yml

annotated-policy.wasm: policy.wasm metadata.yml
	kwctl annotate -m metadata.yml -u README.md -o annotated-policy.wasm policy.wasm

golangci-lint: $(GOLANGCI_LINT) ## Install a local copy of golang ci-lint.
$(GOLANGCI_LINT): $(BIN_DIR) ## Install golangci-lint.
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
	rm -f policy.wasm annotated-policy.wasm artifacthub-pkg.yml

.PHONY: e2e-tests
e2e-tests: annotated-policy.wasm
	bats e2e.bats
