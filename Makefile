MODULE   := github.com/damienstuart/fwknop-go
BIN_DIR  := bin
GIT_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

CLIENT   := $(BIN_DIR)/fwknop
SERVER   := $(BIN_DIR)/fwknopd
CONVERT  := $(BIN_DIR)/fwknop-convert

GO       := go
GOFLAGS  ?=
LDFLAGS  ?= -s -w

# Install locations (override on the command line, e.g. make install-systemd PREFIX=/usr)
PREFIX     ?= /usr/local
SYSCONFDIR ?= /etc/fwknop
UNITDIR    ?= /etc/systemd/system
INSTALL    ?= install

.PHONY: all lib client server convert clean test retest vet fmt tidy install \
	install-systemd uninstall-systemd help

all: client server convert  ## Build all binaries

lib:  ## Build and verify the fkospa library (version from git tag)
	$(GO) build $(GOFLAGS) -ldflags "-X $(MODULE)/fkospa.Version=$(GIT_VERSION)" ./fkospa/...

client:  ## Build the fwknop client
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(CLIENT) ./cmd/fwknop

server:  ## Build the fwknopd server
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(SERVER) ./cmd/fwknopd

convert:  ## Build the fwknop-convert utility
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(CONVERT) ./cmd/fwknop-convert

install:  ## Install binaries to $GOPATH/bin
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/fwknop
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/fwknopd
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/fwknop-convert

install-systemd: server  ## Install fwknopd binary, systemd unit, and sample configs
	$(INSTALL) -d $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) -m 0755 $(SERVER) $(DESTDIR)$(PREFIX)/bin/fwknopd
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/actions
	$(INSTALL) -m 0644 conf_files/server.yaml $(DESTDIR)$(SYSCONFDIR)/server.yaml.sample
	$(INSTALL) -m 0600 conf_files/access.yaml $(DESTDIR)$(SYSCONFDIR)/access.yaml.sample
	$(INSTALL) -m 0644 conf_files/actions/*.yaml $(DESTDIR)$(SYSCONFDIR)/actions/
	$(INSTALL) -d $(DESTDIR)$(UNITDIR)
	$(INSTALL) -m 0644 systemd/fwknopd.service $(DESTDIR)$(UNITDIR)/fwknopd.service
	@echo
	@echo "Installed fwknopd and the systemd unit."
	@echo "Next steps:"
	@echo "  1. cp $(SYSCONFDIR)/server.yaml.sample $(SYSCONFDIR)/server.yaml   # and edit"
	@echo "  2. cp $(SYSCONFDIR)/access.yaml.sample $(SYSCONFDIR)/access.yaml   # add your keys"
	@echo "  3. systemctl daemon-reload"
	@echo "  4. systemctl enable --now fwknopd"

uninstall-systemd:  ## Stop and remove the fwknopd systemd unit and binary
	-systemctl disable --now fwknopd 2>/dev/null || true
	rm -f $(DESTDIR)$(UNITDIR)/fwknopd.service
	rm -f $(DESTDIR)$(PREFIX)/bin/fwknopd
	-systemctl daemon-reload 2>/dev/null || true
	@echo "Removed fwknopd unit and binary. Config under $(SYSCONFDIR) was left in place."

TESTPKGS := $(shell $(GO) list ./... | grep -v /examples/)

test:  ## Run all tests (may use cache)
	$(GO) test $(TESTPKGS)

retest:  ## Run all tests (no cache)
	$(GO) test -count=1 $(TESTPKGS)

vet:  ## Run go vet
	$(GO) vet ./...

fmt:  ## Run gofmt on all Go files
	gofmt -s -w .

tidy:  ## Tidy module dependencies
	$(GO) mod tidy

clean:  ## Remove build artifacts
	rm -rf $(BIN_DIR)

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
