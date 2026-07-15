# Native LD_PRELOAD + seccomp user-notification injector.

SHELL := /usr/bin/env bash

BIN_DIR ?= $(abspath ../bin)
BUILD_DIR := $(abspath ./build)
CC ?= gcc

CPPFLAGS += -I../dispatcher/include
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=gnu11 -fPIC -pthread
LDFLAGS ?= -shared -Wl,-soname,libvclgo_preload.so -Wl,-z,defs -pthread
LDLIBS += -L$(BIN_DIR) -lvclgo_dispatcher -ldl \
          -Wl,-rpath,'$$ORIGIN'

LIB := $(BIN_DIR)/libvclgo_preload.so
OBJ := $(BUILD_DIR)/preload.o

.PHONY: all clean
all: $(LIB)

$(LIB): $(OBJ) $(BIN_DIR)/libvclgo_dispatcher.so | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)
	@echo "[preload] built $@"

$(OBJ): preload.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $@

$(BIN_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(LIB)
