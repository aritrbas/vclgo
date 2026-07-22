# Fastpath preload build (Approach #4). Produces libvclgo_gum_vcl.so, the
# only shipping preload for vclgo. The additional M1..M3 targets below are
# development artifacts (probes and identity/trace variants) kept for
# diagnostic bring-up work; they are not required for the shipping build.

SHELL := /usr/bin/env bash

BUILD_DIR := $(abspath ./build)
CC ?= gcc

CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=gnu11

# --- frida-gum devkit (vendored, not a system dep) ---
# 17.16.0, glibc build. Extracted under vendor/frida-gum-17.16.0/.
GUM_DIR := $(abspath ./vendor/frida-gum-17.16.0)
GUM_HDR := $(GUM_DIR)/frida-gum.h
GUM_LIB := $(GUM_DIR)/libfrida-gum.a

PROBE := $(BUILD_DIR)/probe_sites
GUM_PROBE_LIB := $(BUILD_DIR)/libvclgo_gum_probe.so
GUM_M2_LIB := $(BUILD_DIR)/libvclgo_gum_m2.so
GUM_M25_LIB := $(BUILD_DIR)/libvclgo_gum_m25.so
GUM_FULL_LIB := $(BUILD_DIR)/libvclgo_gum_full.so
GUM_M3_LIB := $(BUILD_DIR)/libvclgo_gum_m3.so
GUM_VCL_LIB := $(BUILD_DIR)/libvclgo_gum_vcl.so

# CFLAGS for the gum probe: -Wno-cast-function-type quiets warnings that
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

.PHONY: all clean probe gum_probe gum_m2 gum_m25 gum_full gum_m3 gum_vcl
all: probe gum_probe gum_m2 gum_m25 gum_full gum_m3 gum_vcl
probe: $(PROBE)
gum_probe: $(GUM_PROBE_LIB)
gum_m2: $(GUM_M2_LIB)
gum_m25: $(GUM_M25_LIB)
gum_full: $(GUM_FULL_LIB)
gum_m3: $(GUM_M3_LIB)
gum_vcl: $(GUM_VCL_LIB)

$(PROBE): probe_sites.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(GUM_PROBE_LIB): gum_probe.c $(GUM_HDR) $(GUM_LIB) | $(BUILD_DIR)
	$(CC) $(GUM_CFLAGS) -I$(GUM_DIR) -shared -Wl,-soname,libvclgo_gum_probe.so \
	    -o $@ $< -L$(GUM_DIR) $(GUM_LDLIBS)

$(GUM_M2_LIB): gum_m2.c $(GUM_HDR) $(GUM_LIB) | $(BUILD_DIR)
	$(CC) $(GUM_CFLAGS) -I$(GUM_DIR) -shared -Wl,-soname,libvclgo_gum_m2.so \
	    -o $@ $< -L$(GUM_DIR) $(GUM_LDLIBS)

$(GUM_M25_LIB): gum_m25.c $(GUM_HDR) $(GUM_LIB) | $(BUILD_DIR)
	$(CC) $(GUM_CFLAGS) -I$(GUM_DIR) -shared -Wl,-soname,libvclgo_gum_m25.so \
	    -o $@ $< -L$(GUM_DIR) $(GUM_LDLIBS)

$(GUM_FULL_LIB): gum_full.c $(GUM_HDR) $(GUM_LIB) | $(BUILD_DIR)
	$(CC) $(GUM_CFLAGS) -I$(GUM_DIR) -shared -Wl,-soname,libvclgo_gum_full.so \
	    -o $@ $< -L$(GUM_DIR) $(GUM_LDLIBS)

$(GUM_M3_LIB): gum_m3.c $(GUM_HDR) $(GUM_LIB) | $(BUILD_DIR)
	$(CC) $(GUM_CFLAGS) -I$(GUM_DIR) -shared -Wl,-soname,libvclgo_gum_m3.so \
	    -o $@ $< -L$(GUM_DIR) $(GUM_LDLIBS)

$(GUM_VCL_LIB): gum_vcl.c $(GUM_HDR) $(GUM_LIB) | $(BUILD_DIR)
	$(CC) $(GUM_VCL_CFLAGS) -I$(GUM_DIR) -shared \
	    -Wl,-soname,libvclgo_gum_vcl.so \
	    -o $@ $< -L$(GUM_DIR) $(GUM_VCL_LDLIBS)

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
