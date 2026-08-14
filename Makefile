# SPDX-FileCopyrightText: 2026 UNSW
#
# SPDX-License-Identifier: BSD-2-Clause

CLANG_FORMAT ?= clang-format
CLANG_TIDY ?= clang-tidy
STYLE_GOALS := format format-check

LIBTRUSTEDLO_PATH ?= $(CURDIR)
MICROKIT_BOARD ?= qemu_virt_aarch64
MICROKIT_CONFIG ?= debug
CPU ?= cortex-a53
TARGET ?= aarch64-none-elf
LLVM ?= 1

ifeq ($(filter $(STYLE_GOALS),$(MAKECMDGOALS)),)
ifndef MICROKIT_SDK
$(error MICROKIT_SDK is not set)
endif

ifndef BUILD_DIR
$(error BUILD_DIR is not set)
endif
endif

LIBTRUSTEDLO_PATH ?= $(CURDIR)
.DEFAULT_GOAL := all

BOARD_DIR := \
	$(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

REUSE ?= reuse

ifdef LLVM
CC := clang
LD := ld.lld
AR := llvm-ar

ARCH_CFLAGS := \
    -target $(TARGET) \
    -Wno-unused-command-line-argument

ARCH_LDFLAGS :=
else
ifndef TOOLCHAIN
$(error TOOLCHAIN must be specified for a non-LLVM build)
endif

CC := $(TOOLCHAIN)-gcc
LD := $(TOOLCHAIN)-ld
AR := $(TOOLCHAIN)-ar

ARCH_CFLAGS :=
ARCH_LDFLAGS :=
endif

export CC
export LD
export AR
export ARCH_CFLAGS
export ARCH_LDFLAGS
export BOARD_DIR
export BUILD_DIR
export LIBTRUSTEDLO_PATH

LIB_BUILD_DIR := $(BUILD_DIR)/libtrustedlo
CFG_GEN_DIR := $(LIB_BUILD_DIR)/generated

LIBTRUSTEDLO := $(LIB_BUILD_DIR)/libtrustedlo.a
LIB_SRC_DIR := $(LIBTRUSTEDLO_PATH)/src

TRAMPOLINE_ELF := \
	$(LIB_BUILD_DIR)/trampoline.elf

LOADER_ELF := \
	$(LIB_BUILD_DIR)/protocon.elf

LIB_SOURCES := \
	trustedlo_cfuncs.c \
	trustedlo_mfuncs.c \
	cap.c \
	xrt.c \
	miscutils.c \
	memory.c

LIB_OBJECTS := \
	$(patsubst %.c,$(LIB_BUILD_DIR)/%.o,$(LIB_SOURCES))

LIB_CFLAGS := \
	$(ARCH_CFLAGS) \
	-ffreestanding \
	-fno-builtin \
	-fno-stack-protector \
	-O3 \
	-g \
	-Wall \
	-Werror \
	-I$(CFG_GEN_DIR) \
	-I$(BOARD_DIR)/include \
	-I$(LIBTRUSTEDLO_PATH)/include

# ========================================================
# Generated VM layout
# ========================================================

VM_LAYOUT_CONFIG ?= \
	$(LIBTRUSTEDLO_PATH)/config/vm_layout.py

VM_LAYOUT_GEN := \
	$(LIBTRUSTEDLO_PATH)/tools/gen_vm_layout.py

VM_LAYOUT_HEADER := \
    $(CFG_GEN_DIR)/tsldr_vm_layout.h

VM_LAYOUT_LINKER_SCRIPT := \
    $(CFG_GEN_DIR)/tsldr_vm_layout.ld

export CFG_GEN_DIR
export VM_LAYOUT_HEADER
export VM_LAYOUT_LINKER_SCRIPT

$(VM_LAYOUT_HEADER): $(VM_LAYOUT_CONFIG) $(VM_LAYOUT_GEN)
	@mkdir -p $(dir $@)
	python3 -B $(VM_LAYOUT_GEN) \
	    --config $(VM_LAYOUT_CONFIG) \
	    --header-output $@

$(VM_LAYOUT_LINKER_SCRIPT): $(VM_LAYOUT_CONFIG) $(VM_LAYOUT_GEN)
	@mkdir -p $(dir $@)
	python3 -B $(VM_LAYOUT_GEN) \
	    --config $(VM_LAYOUT_CONFIG) \
	    --linker-output $@

.PHONY: header
header: $(VM_LAYOUT_HEADER) $(VM_LAYOUT_LINKER_SCRIPT)

include $(LIBTRUSTEDLO_PATH)/trampoline/tp.mk


LICENSE_C_FILES := \
	$(wildcard src/*.c) \
	$(wildcard include/*.h) \
	$(wildcard loader/*.c) \
	$(wildcard trampoline/*.c)

license-annotate-c:
	$(REUSE) annotate --style=c --multi-line \
		--copyright="UNSW" --year=2026 \
		--license=BSD-2-Clause $(LICENSE_C_FILES)

LICENSE_FILES := $(shell git ls-files \
	'*.py' \
	'*.mk' \
	'Makefile' \
	'.clang-format' \
	'.gitignore' \
	'.github/*.yml' \
	'.github/**/*.yml' \
	'.localtest/*.sh')

license-annotate-others:
	$(REUSE) annotate \
		--copyright="UNSW" --year=2026 \
		--license=BSD-2-Clause \
		--skip-unrecognised \
		$(LICENSE_FILES)

license-check:
	$(REUSE) lint

license-annotate: license-annotate-c license-annotate-others

.PHONY: all library trampoline loader clean format format-check tidy \
	license-check license-annotate license-annotate-c license-annotate-others

all: trampoline library loader

library: $(LIBTRUSTEDLO)

$(LIB_BUILD_DIR):
	@mkdir -p $@

$(LIB_BUILD_DIR)/%.o: $(LIB_SRC_DIR)/%.c  $(VM_LAYOUT_HEADER)
	@mkdir -p $(dir $@)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(LIBTRUSTEDLO): $(LIB_OBJECTS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

include $(LIBTRUSTEDLO_PATH)/loader/ld.mk

FORMAT_FILES := \
	$(addprefix $(LIB_SRC_DIR)/,$(LIB_SOURCES)) \
	$(wildcard $(LIBTRUSTEDLO_PATH)/include/*.h) \
	$(TRAMPOLINE_SRC) \
	$(TSLDR_LD_SRC)

format:
	$(CLANG_FORMAT) -i $(FORMAT_FILES)

format-check:
	$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_FILES)

tidy: $(VM_LAYOUT_HEADER)
	$(CLANG_TIDY) \
		$(addprefix $(LIB_SRC_DIR)/,$(LIB_SOURCES)) \
		-- $(LIB_CFLAGS)
	$(CLANG_TIDY) $(TRAMPOLINE_SRC) -- $(TRAMPOLINE_CFLAGS)
	$(CLANG_TIDY) $(TSLDR_LD_SRC) -- $(TSLDR_LD_CFLAGS)


clean:
	rm -rf $(LIB_BUILD_DIR)