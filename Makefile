
ifndef MICROKIT_SDK
$(error MICROKIT_SDK is not set)
endif

ifndef BUILD_DIR
$(error BUILD_DIR is not set)
endif

ifndef MICROKIT_BOARD
$(error MICROKIT_BOARD is not set)
endif

ifndef MICROKIT_CONFIG
$(error MICROKIT_CONFIG is not set)
endif

ifndef CPU
$(error CPU is not set)
endif

ifndef TARGET
$(error TARGET is not set)
endif

LIBTRUSTEDLO_PATH ?= $(CURDIR)
.DEFAULT_GOAL := all

BOARD_DIR := \
	$(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

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

TRAMPOLINE_ELF := \
	$(LIB_BUILD_DIR)/trampoline.elf

LOADER_ELF := \
	$(LIB_BUILD_DIR)/protocon.elf

LIB_SOURCES := \
	trustedloader.c \
	caputils.c \
	acrtutils.c \
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
	-Wno-unused-function \
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

.PHONY: all library trampoline loader clean

all: trampoline library loader

library: $(LIBTRUSTEDLO)

$(LIB_BUILD_DIR):
	@mkdir -p $@

$(LIB_BUILD_DIR)/%.o: \
    $(LIBTRUSTEDLO_PATH)/%.c \
    $(VM_LAYOUT_HEADER)
	@mkdir -p $(dir $@)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(LIBTRUSTEDLO): $(LIB_OBJECTS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

include $(LIBTRUSTEDLO_PATH)/loader/ld.mk

clean:
	rm -rf $(LIB_BUILD_DIR)