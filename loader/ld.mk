
ifndef LIBTRUSTEDLO_PATH 
$(error LIBTRUSTEDLO_PATH is not set)
endif

ifndef LIB_BUILD_DIR 
$(error LIB_BUILD_DIR is not set)
endif

CFG_GEN_DIR ?= $(LIB_BUILD_DIR)/generated
LIBTRUSTEDLO ?= $(LIB_BUILD_DIR)/libtrustedlo.a

TSLDR_LD_ELF ?= $(LIB_BUILD_DIR)/loader.elf
TSLDR_LD_SRC := $(LIBTRUSTEDLO_PATH)/loader/loader.c
LINKER_SCRIPT  := $(LIBTRUSTEDLO_PATH)/loader/ld.lds
TSLDR_LD_OBJS := \
	$(LIB_BUILD_DIR)/loader.o
MISC_OBJS := \
	$(LIB_BUILD_DIR)/memory.o

TSLDR_LD_CFLAGS := \
	$(ARCH_CFLAGS) \
	-ffreestanding \
	-fno-builtin \
	-fno-stack-protector \
	-fno-pic \
	-fno-pie \
	-fno-asynchronous-unwind-tables \
	-fno-unwind-tables \
	-O2 \
	-g \
	-Wall \
	-Wextra \
	-Werror \
	-I$(CFG_GEN_DIR) \
	-I$(BOARD_DIR)/include \
	-I$(LIBTRUSTEDLO_PATH)/include

TSLDR_LD_LDFLAGS := \
	$(ARCH_LDFLAGS) \
	-nostdlib \
	-static \
	-no-pie \
	--gc-sections \
	-T$(LINKER_SCRIPT) \
	-L$(BOARD_DIR)/lib

loader: $(TSLDR_LD_ELF)

$(TSLDR_LD_OBJS): $(TSLDR_LD_SRC) | $(LIB_BUILD_DIR)
	$(CC) $(TSLDR_LD_CFLAGS) \
		-ffunction-sections \
		-fdata-sections \
		-c $< -o $@

$(TSLDR_LD_ELF): $(TSLDR_LD_OBJS) $(MISC_OBJS) $(LINKER_SCRIPT) $(LIBTRUSTEDLO)
	$(LD) $(TSLDR_LD_LDFLAGS) \
		$(TSLDR_LD_OBJS) $(MISC_OBJS) $(LIBTRUSTEDLO) -lmicrokit \
		-o $@

-include $(TSLDR_LD_OBJS:.o=.d)
