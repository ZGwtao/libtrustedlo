INCLUDE tsldr_vm_layout.ld

ENTRY(loader_entry)

PHDRS
{
    text PT_LOAD FLAGS(5); /* R | X */
    data PT_LOAD FLAGS(6); /* R | W */
}

SECTIONS
{
    . = TSLDR_VM_LOADER_PROGRAM_BASE;
    __loader_image_start = .;

    .text : ALIGN(16)
    {
        KEEP(*(.text.loader_entry))
        *(.text .text.*)
    } :text

    .rodata : ALIGN(16)
    {
        *(.rodata .rodata.*)
    } :text

    .data : ALIGN(16)
    {
        *(.data .data.*)
    } :data

    .bss : ALIGN(16)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    __loader_image_end = .;

    ASSERT(
        __loader_image_end <= TSLDR_VM_LOADER_PROGRAM_END,
        "loader image exceeds LOADER_PROGRAM VM region"
    )

    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}