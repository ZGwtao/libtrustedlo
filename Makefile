
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

ifndef LIBTRUSTEDLO_PATH
$(error LIBTRUSTEDLO_PATH is not set)
endif

ifdef LLVM
CC := clang
LD := ld.lld
LIBTSLDR_CFLAGS = -target $(TARGET) -Wno-unused-command-line-argument
else
ifndef TOOLCHAIN
$(error your TOOLCHAIN triple must be specified for non-LLVM toolchain setup. E.g. TOOLCHAIN = aarch64-none-elf)
else

CC ?= $(TOOLCHAIN)-gcc
LD ?= $(TOOLCHAIN)-ld
LIBTSLDR_LDFLAGS =

endif
endif

BOARD_DIR ?= $(MICROKIT_SDK)/board/$(MICROKIT_BOARD)/$(MICROKIT_CONFIG)

TSLDR_OBJS :=  \
	trustedloader.o \
	caputils.o acrtutils.o miscutils.o

LIBTSLDR_SRC_DIR ?= $(LIBTRUSTEDLO_PATH)
LIBTSLDR_BUILD_DIR := $(BUILD_DIR)/libtrustedlo
LIBTSLDR_OBJS := $(addprefix $(LIBTSLDR_BUILD_DIR)/,$(TSLDR_OBJS))
LIBTSLDR := $(LIBTSLDR_BUILD_DIR)/libtrustedlo.a

LIBTSLDR_CFLAGS += -nostdlib -ffreestanding -g -O3 \
          			-Wall -Wno-unused-function -Werror \
          			-I$(BOARD_DIR)/include \
					-I$(LIBTSLDR_SRC_DIR)/include

all: $(LIBTSLDR)

# Build directory as a real target
$(LIBTSLDR_BUILD_DIR):
	mkdir -p $@

# Object rules depend on the directory, not a phony
$(LIBTSLDR_BUILD_DIR)/%.o: $(LIBTSLDR_SRC_DIR)/%.c | $(LIBTSLDR_BUILD_DIR)
	$(CC) -c $(LIBTSLDR_CFLAGS) $< -o $@

# Archive rule
$(LIBTSLDR): $(LIBTSLDR_OBJS)
	$(LD) $(LIBTSLDR_LDFLAGS) -r $^ -o $@
	rm $(LIBTSLDR_OBJS)
