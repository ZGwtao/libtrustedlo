
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
LIBTRUSTEDLO  := $(LIB_BUILD_DIR)/libtrustedlo.a

TRAMPOLINE_ELF := \
	$(LIB_BUILD_DIR)/trampoline.elf

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
	-I$(BOARD_DIR)/include \
	-I$(LIBTRUSTEDLO_PATH)/include

include $(LIBTRUSTEDLO_PATH)/trampoline/tp.mk

.PHONY: all trampoline library clean

all: trampoline library 

library: $(LIBTRUSTEDLO)

$(LIB_BUILD_DIR):
	mkdir -p $@

$(LIB_BUILD_DIR)/%.o: $(LIBTRUSTEDLO_PATH)/%.c
	mkdir -p $(dir $@)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(LIBTRUSTEDLO): $(LIB_OBJECTS)
	$(AR) rcs $@ $^

clean:
	rm -rf $(LIB_BUILD_DIR)