# dispatcher/Makefile — builds libvclgo_dispatcher.so from POSIX C11.

SHELL := /usr/bin/env bash

BIN_DIR   ?= $(abspath ../bin)
BUILD_DIR := $(abspath ./build)

# Keep this source list explicit so only the native dispatcher ABI enters the
# built library; do not replace it with a wildcard.
SRC := src/addr.c src/api_native.c src/lifecycle_native.c \
       src/pool_native.c src/registry_native.c
OBJ := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SRC))
DEP := $(OBJ:.o=.d)

# Pull VPP flags via pkg-config; the repo's pkgconfig/ dir is prepended in
# the top-level Makefile. Fail loudly if it isn't resolvable.
VPPCOM_CFLAGS := $(shell pkg-config --cflags vppcom 2>/dev/null)
VPPCOM_LIBS   := $(shell pkg-config --libs   vppcom 2>/dev/null)
ifeq ($(strip $(VPPCOM_CFLAGS)),)
$(error "pkg-config could not find vppcom; run 'make pc VPP_PREFIX=/path/to/vpp' at repo root")
endif

CC       ?= gcc
CFLAGS   ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11 -fPIC \
            -D_GNU_SOURCE -pthread
CPPFLAGS += -Iinclude -Isrc $(VPPCOM_CFLAGS)
LDFLAGS  ?= -shared -Wl,-soname,libvclgo_dispatcher.so -pthread
LDLIBS   ?= $(VPPCOM_LIBS)

SANITIZE ?= 0
ifeq ($(SANITIZE),1)
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

LIB := $(BIN_DIR)/libvclgo_dispatcher.so

.PHONY: all
all: $(LIB)

$(LIB): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@echo "[dispatcher] built $@"

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -c -o $@ $<

# Session and request layouts are shared across translation units. Rebuild
# every affected object when one of those headers changes; stale layouts can
# otherwise link successfully and corrupt heap/session state at runtime.
-include $(DEP)

$(BUILD_DIR):
	mkdir -p $@

$(BIN_DIR):
	mkdir -p $@

.PHONY: install
install: $(LIB)
	@echo "install to $(PREFIX)/lib …"
	install -Dm755 $(LIB) $(PREFIX)/lib/libvclgo_dispatcher.so
	install -Dm644 include/vclgo.h $(PREFIX)/include/vclgo.h

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f  $(LIB)
