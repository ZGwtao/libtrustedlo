ifndef LIBTRUSTEDLO_PATH
$(error LIBTRUSTEDLO_PATH is not set)
endif

ifndef LIB_BUILD_DIR
$(error LIB_BUILD_DIR is not set)
endif

CFG_GEN_DIR ?= $(LIB_BUILD_DIR)/generated

VM_LAYOUT_HEADER ?= \
    $(CFG_GEN_DIR)/tsldr_vm_layout.h

VM_LAYOUT_LINKER_SCRIPT ?= \
    $(CFG_GEN_DIR)/tsldr_vm_layout.ld

TRAMPOLINE_ELF ?= $(LIB_BUILD_DIR)/trampoline.elf

TRAMPOLINE_SRC := \
	$(LIBTRUSTEDLO_PATH)/trampoline/trampoline.c

TRAMPOLINE_LINKER_SCRIPT := \
	$(LIBTRUSTEDLO_PATH)/trampoline/trampoline.lds

TRAMPOLINE_OBJS := \
	$(LIB_BUILD_DIR)/trampoline.o
MISC_OBJS := \
	$(LIB_BUILD_DIR)/memory.o

TRAMPOLINE_CFLAGS := \
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
	-MMD \
	-MP \
	-I$(CFG_GEN_DIR) \
	-I$(BOARD_DIR)/include \
	-I$(LIBTRUSTEDLO_PATH)/include

TRAMPOLINE_LDFLAGS := \
	$(ARCH_LDFLAGS) \
	-nostdlib \
	-static \
	-no-pie \
	--gc-sections \
	-L$(CFG_GEN_DIR) \
	-T$(TRAMPOLINE_LINKER_SCRIPT)

trampoline: $(TRAMPOLINE_ELF)

$(TRAMPOLINE_OBJS): $(TRAMPOLINE_SRC) $(VM_LAYOUT_HEADER) | $(LIB_BUILD_DIR)
	$(CC) $(TRAMPOLINE_CFLAGS) \
		-ffunction-sections \
		-fdata-sections \
		-c $< -o $@

$(TRAMPOLINE_ELF): \
	$(TRAMPOLINE_OBJS) \
    $(MISC_OBJS) \
    $(TRAMPOLINE_LINKER_SCRIPT) \
	$(VM_LAYOUT_LINKER_SCRIPT)
	$(LD) $(TRAMPOLINE_LDFLAGS) \
		$(TRAMPOLINE_OBJS) \
		$(MISC_OBJS) \
		-o $@

-include $(TRAMPOLINE_OBJS:.o=.d)