# SPDX-License-Identifier: BSD-3-Clause
# Standalone build against an installed DPDK (pkg-config libdpdk).
#   make            -> build/mitm-delay
# Requires DPDK >= 21.11 dev files (Ubuntu 22.04: `apt install dpdk-dev`,
# or a self-built/installed DPDK on PKG_CONFIG_PATH). No driver patch needed.

APP = mitm-delay
SRCS-y := mitm_delay.c

PKGCONF ?= pkg-config

ifeq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS  += -O3 -Wall $(shell $(PKGCONF) --cflags libdpdk)
CFLAGS  += -DALLOW_EXPERIMENTAL_API
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	-rmdir build 2>/dev/null || true

else # no installed DPDK

$(error "No installed DPDK found (pkg-config can't find libdpdk). \
Install dpdk-dev or set PKG_CONFIG_PATH to your DPDK install's pkgconfig dir.")

endif
