# Original from github.com/lainio/err2

PKG1 := github.com/lainio/ic/chain
PKG2 := github.com/lainio/ic/node
PKG3 := github.com/lainio/ic/identity
PKG4 := github.com/lainio/ic/hop
PKG5 := github.com/lainio/ic/key
PKGS := $(PKG1) $(PKG2) $(PKG3) $(PKG4) $(PKG5)

SRCDIRS := $(shell go list -f '{{.Dir}}' $(PKGS))

MAX_LINE ?= 80
GO := go
#GO := go1.18beta1
TEST_ARGS ?= -benchmem

check: lint test

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

test1:
	$(GO) test $(TEST_ARGS) $(PKG1)

test2:
	$(GO) test $(TEST_ARGS) $(PKG2)

test3:
	$(GO) test $(TEST_ARGS) $(PKG3)

test4:
	$(GO) test $(TEST_ARGS) $(PKG4)

test5:
	$(GO) test $(TEST_ARGS) $(PKG5)

test:
	$(GO) test $(TEST_ARGS) $(PKGS)

testv:
	$(GO) test $(TEST_ARGS) $(PKGS) -v

testj:
	$(GO) test $(TEST_ARGS) $(PKGS) -json

bench:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKGS)

bench1:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG1)

bench2:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG2)

bench3:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG3)

bench5:
	@$(GO) test $(TEST_ARGS) -bench=. $(PKG5)

vet: | test
	@$(GO) vet $(PKGS)

fmt:
	@golines -t 5 -w -m $(MAX_LINE) --ignore-generated .

dry-fmt:
	@golines -t 5 --dry-run -m $(MAX_LINE) --ignore-generated .

gofmt:
	@echo Checking code is gofmted
	@test -z "$(shell gofmt -s -l -d -e $(SRCDIRS) | tee /dev/stderr)"

lint:
	golangci-lint run

