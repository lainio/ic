# Original from github.com/lainio/err2

PKGS := ./...
# PKGS2 := github.com/lainio/ic/node
SRCDIRS := $(shell go list -f '{{.Dir}}' $(PKGS))

GO := go
#GO := go1.18beta1

deps:
	$(GO) get -t ./...

check: test vet gofmt misspell unconvert staticcheck ineffassign unparam

test:
	$(GO) test $(PKGS) $(PKGS2)

bench:
	$(GO) test -bench=. $(PKGS) $(PKGS2)

bench1:
	$(GO) test -bench=. $(PKGS)

bench2:
	$(GO) test -bench=. $(PKGS2)

vet: | test
	$(GO) vet $(PKGS) $(PKGS2)

staticcheck:
	$(GO) get honnef.co/go/tools/cmd/staticcheck
	staticcheck -checks all $(PKGS) $(PKGS2)

misspell:
	$(GO) get github.com/client9/misspell/cmd/misspell
	misspell \
		-locale GB \
		-error \
		*.md *.go

unconvert:
	$(GO) get github.com/mdempsky/unconvert
	unconvert -v $(PKGS)

ineffassign:
	$(GO) get github.com/gordonklaus/ineffassign
	find $(SRCDIRS) -name '*.go' | xargs ineffassign

pedantic: check errcheck

unparam:
	$(GO) get mvdan.cc/unparam
	unparam ./...

errcheck:
	$(GO) get github.com/kisielk/errcheck
	errcheck $(PKGS)

gofmt:
	@echo Checking code is gofmted
	@test -z "$(shell gofmt -s -l -d -e $(SRCDIRS) | tee /dev/stderr)"
