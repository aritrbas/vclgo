# Top-level orchestrator for vclgo.
#
# vclgo ships one backend: the Approach #4 in-process Frida-Gum fastpath
# preload (libvclgo_gum_vcl.so), built from preload/fastpath.
#
# `make pc VPP_PREFIX=/path/to/vpp` renders pkgconfig/vppcom.pc for a specific
# VPP install; every other target picks it up automatically via
# PKG_CONFIG_PATH.

SHELL := /usr/bin/env bash

REPO_DIR   := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PKGCFG_DIR := $(REPO_DIR)/pkgconfig
BIN_DIR    := $(REPO_DIR)/bin

VPP_PREFIX     ?= /home/aritrbas/vpp/vpp/build-root/install-vpp-native/vpp
VPP_LIBDIR     ?= $(VPP_PREFIX)/lib/x86_64-linux-gnu
VPP_INCLUDEDIR ?= $(VPP_PREFIX)/include
VPP_VERSION    ?= 0.0.0

# Prepend our pkgconfig unless the caller asks us not to.
ifneq ($(VCLGO_SKIP_PC),1)
export PKG_CONFIG_PATH := $(PKGCFG_DIR):$(PKG_CONFIG_PATH)
endif

.PHONY: all
all: build

.PHONY: pc
pc:
	@mkdir -p "$(PKGCFG_DIR)"
	@sed -e 's|@VPP_PREFIX@|$(VPP_PREFIX)|g' \
	     -e 's|@VPP_LIBDIR@|$(VPP_LIBDIR)|g' \
	     -e 's|@VPP_INCLUDEDIR@|$(VPP_INCLUDEDIR)|g' \
	     -e 's|@VPP_VERSION@|$(VPP_VERSION)|g' \
	     "$(PKGCFG_DIR)/vppcom.pc.in" > "$(PKGCFG_DIR)/vppcom.pc"
	@echo "[pc] rendered $(PKGCFG_DIR)/vppcom.pc for $(VPP_PREFIX)"

.PHONY: dispatcher
dispatcher: pc
	@$(MAKE) -C dispatcher BIN_DIR="$(BIN_DIR)"

# Approach #4 in-process fastpath preload — builds libvclgo_gum_vcl.so from
# preload/fastpath. Links against libvclgo_dispatcher.so from ./dispatcher.
.PHONY: fastpath
fastpath: dispatcher
	@$(MAKE) -C preload/fastpath gum_vcl

.PHONY: examples
examples:
	@mkdir -p "$(BIN_DIR)/examples"
	@for ex in echo_server echo_client http_server http_client \
	           udp_echo_server udp_echo_client; do \
	    echo "[examples] building $$ex"; \
	    go build -o "$(BIN_DIR)/examples/$$ex" ./examples/$$ex; \
	done

.PHONY: build
build: pc dispatcher fastpath examples

# Descriptive alias used by the documentation and test workflow.
.PHONY: build-fastpath
build-fastpath: build

.PHONY: test
test:
	@bash test/run_smoke_fastpath.sh

.PHONY: fmt
fmt:
	gofmt -w examples

.PHONY: vet
vet:
	go vet ./...

.PHONY: clean
clean:
	rm -rf "$(BIN_DIR)"
	@$(MAKE) -C dispatcher clean 2>/dev/null || true
	@$(MAKE) -C preload/fastpath clean 2>/dev/null || true
	rm -f "$(PKGCFG_DIR)/vppcom.pc"
