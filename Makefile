# Original from github.com/lainio/err2

PKG ?= ./...

PKG_PATH := github.com/lainio/ic/chain
PKG_NODE_CMD := github.com/lainio/ic/cmds/node
PKG_NODE := github.com/lainio/ic/internal/nodeidentity
PKG_HOP := github.com/lainio/ic/hop
PKG_KEY := github.com/lainio/ic/key
PKG_CORE := github.com/lainio/ic/internal/core/...
PKG_STORAGE := github.com/lainio/ic/storage/...
PKG_INTERNAL := github.com/lainio/ic/internal/...
PKG_PW := github.com/lainio/ic/internal/pw/...

PKGS := ./...

MAX_LINE ?= 80
GO := go
#GO := go1.18beta1
TEST_ARGS ?= 

check: lint test cli

.PHONY: build cli install deps test
cli:
	$(eval VERSION = $(shell printf "Build v.%s on %s" "$(shell cat ./VERSION)" "$(shell date)"))
	@echo "Installing version '$(VERSION)' of 'tdc'"
	go build \
		-ldflags "-X 'github.com/lainio/ic/utils.Version=$(VERSION)'" \
		-o $(GOPATH)/bin/tdc \
		cmd/tdc/tdc.go

install:
	$(eval VERSION = $(shell printf "Build v.%s on %s" "$(shell cat ./VERSION)" "$(shell date)"))
	@echo "Installing version $(VERSION) of 'ic'"
	go install \
		-ldflags "-X 'github.com/lainio/ic/utils.Version=$(VERSION)'" \
		cmd/tdc/tdc.go

build:
	@$(GO) build -o /dev/null $(PKGS)

deps:
	@$(GO) get -t ./...

test_pkg:
	$(GO) test $(TEST_ARGS) $(PKG)

test_pw:
	$(GO) test $(TEST_ARGS) $(PKG_PW)

test_path:
	$(GO) test $(TEST_ARGS) $(PKG_PATH)

test_node_cmd:
	$(GO) test $(TEST_ARGS) $(PKG_NODE_CMD)

test_node:
	$(GO) test $(TEST_ARGS) $(PKG_NODE)

test_hop:
	$(GO) test $(TEST_ARGS) $(PKG_HOP)

test_key:
	$(GO) test $(TEST_ARGS) $(PKG_KEY)

test_intro:
	$(GO) test $(TEST_ARGS) $(PKG_INTRO)

test_intror:
	$(GO) test -mod=readonly -race -count 1 $(TEST_ARGS) $(PKG_INTRO)

test_storage:
	$(GO) test $(TEST_ARGS) $(PKG_STORAGE)

test_storager:
	$(GO) test -mod=readonly -race -count 1 $(TEST_ARGS) $(PKG_STORAGE)

test_internal:
	$(GO) test $(TEST_ARGS) $(PKG_INTERNAL)

test_internalr:
	$(GO) test -mod=readonly -race -count 1 $(TEST_ARGS) $(PKG_INTERNAL)

test:
	$(GO) test $(TEST_ARGS) $(PKGS)

testv:
	$(GO) test $(TEST_ARGS) $(PKGS) -v

testj:
	$(GO) test $(TEST_ARGS) $(PKGS) -json

testr:
	$(GO) test -mod=readonly -race -count 1 $(TEST_ARGS) $(PKGS)

bench:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKGS)

bench_pw:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG_PW)

bench_path:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG_PATH)

bench_node_cmd:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG_NODE_CMD)

bench_node:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG_NODE)

bench_key:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG_KEY)

bench_intro:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG_INTRO)

bench_storage:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG_STORAGE)

bench_internal:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG_INTERNAL)

vet: | test
	@$(GO) vet $(PKGS)

fmt:
	@golines -t 5 -w -m $(MAX_LINE) --ignore-generated .

dry-fmt:
	@golines -t 5 --dry-run -m $(MAX_LINE) --ignore-generated .

gofmt:
	@echo Checking code is gofmted
	@test -z "$(shell gofmt -s -l -d -e . | tee /dev/stderr)"

lint:
	golangci-lint run

