# Fastpath preload build (Approach #4). Produces libvclgo_gum_vcl.so, the
# only shipping preload for vclgo. The current design is documented in
# docs/architecture.md, docs/architecture_diagrams.md, and
# docs/text_patching.md.

SHELL := /usr/bin/env bash

BUILD_DIR := $(abspath ./build)
CC ?= gcc

CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=gnu11

# --- frida-gum devkit (vendored, not a system dep) ---
# 17.16.0, glibc build. Extracted under vendor/frida-gum-17.16.0/.
GUM_DIR := $(abspath ./vendor/frida-gum-17.16.0)
GUM_HDR := $(GUM_DIR)/frida-gum.h
GUM_LIB := $(GUM_DIR)/libfrida-gum.a

GUM_VCL_LIB := $(BUILD_DIR)/libvclgo_gum_vcl.so

# CFLAGS for the gum build: -Wno-cast-function-type quiets warnings that
# come out of frida-gum.h itself (GCallback casts); we still want -Wall
# -Wextra on our own code.
GUM_CFLAGS := -O2 -g -Wall -Wextra -std=gnu11 -fPIC -pthread \
              -Wno-cast-function-type
GUM_LDLIBS := -l:libfrida-gum.a -lrt -lresolv -ldl -lm -pthread

# gum_vcl.c additionally links against the vclgo dispatcher and needs
# its public header. Bin dir is where the main vclgo build drops
# libvclgo_dispatcher.so; we rpath $ORIGIN so a co-located install
# resolves it without LD_LIBRARY_PATH gymnastics.
DISP_INCLUDE := $(abspath ../../dispatcher/include)
DISP_BIN     := $(abspath ../../bin)
GUM_VCL_CFLAGS := $(GUM_CFLAGS) -I$(DISP_INCLUDE)
GUM_VCL_LDLIBS := $(GUM_LDLIBS) -L$(DISP_BIN) -lvclgo_dispatcher \
                  -Wl,-rpath,$(DISP_BIN) -Wl,-rpath,'$$ORIGIN'

.PHONY: all clean gum_vcl
all: gum_vcl
gum_vcl: $(GUM_VCL_LIB)

$(GUM_VCL_LIB): gum_vcl.c $(GUM_HDR) $(GUM_LIB) | $(BUILD_DIR)
	$(CC) $(GUM_VCL_CFLAGS) -I$(GUM_DIR) -shared \
	    -Wl,-soname,libvclgo_gum_vcl.so \
	    -o $@ $< -L$(GUM_DIR) $(GUM_VCL_LDLIBS)

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
