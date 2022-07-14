# Original from github.com/lainio/err2

PKG1 := github.com/lainio/ic/chain
PKG2 := github.com/lainio/ic/node
PKGS := $(PKG1) $(PKG2) $(PKG3) $(PKG4)

SRCDIRS := $(shell go list -f '{{.Dir}}' $(PKGS))

GO := go
#GO := go1.18beta1

build:
	@$(GO) build -o /dev/null $(PKGS)

deps:
	@$(GO) get -t ./...

test1:
	$(GO) test $(PKG1)

test2:
	$(GO) test $(PKG2)

test:
	$(GO) test $(PKGS)

bench:
	@$(GO) test -bench=. $(PKGS)

bench1:
	@$(GO) test -bench=. $(PKG1)

bench2:
	@$(GO) test -bench=. $(PKG2)

vet: | test
	@$(GO) vet $(PKGS)

gofmt:
	@echo Checking code is gofmted
	@test -z "$(shell gofmt -s -l -d -e $(SRCDIRS) | tee /dev/stderr)"
