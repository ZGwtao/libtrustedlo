/*
 * SPDX-FileCopyrightText: 2026 UNSW
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <memory.h>
#include <miscutils.h>
#include <stdarg.h>

void putc(uint8_t ch)
{
#if defined(CONFIG_PRINTING)
    seL4_DebugPutChar(ch);
#endif
}

void puts(const char *s)
{
    while (*s) {
        putc(*s);
        s++;
    }
}

static char hexchar(unsigned int v)
{
    return v < 10 ? '0' + v : ('a' - 10) + v;
}

void puthex32(uint32_t val)
{
    char buffer[8 + 3];
    buffer[0] = '0';
    buffer[1] = 'x';
    buffer[8 + 3 - 1] = 0;
    for (unsigned i = 8 + 1; i > 1; i--) {
        buffer[i] = hexchar(val & 0xf);
        val >>= 4;
    }
    puts(buffer);
}

void puthex64(uint64_t val)
{
    char buffer[16 + 3];
    buffer[0] = '0';
    buffer[1] = 'x';
    buffer[16 + 3 - 1] = 0;
    for (unsigned i = 16 + 1; i > 1; i--) {
        buffer[i] = hexchar(val & 0xf);
        val >>= 4;
    }
    puts(buffer);
}

static void putuint(uint64_t val, unsigned base, bool upper)
{
    char buf[32];
    unsigned i = sizeof(buf);
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";

    do {
        buf[--i] = digits[val % base];
        val /= base;
    } while (val);

    while (i < sizeof(buf)) {
        microkit_dbg_putc(buf[i++]);
    }
}

static void putint(int64_t val)
{
    uint64_t u;

    if (val < 0) {
        microkit_dbg_putc('-');
        u = -(uint64_t)val;
    } else {
        u = val;
    }

    putuint(u, 10, false);
}

void tsldr_miscutil_dbg_print(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    while (*format) {
        if (*format != '%') {
            microkit_dbg_putc(*format++);
            continue;
        }

        format++;

        int precision = -1;
        if (*format == '.') {
            format++;
            precision = 0;

            if (*format == '*') {
                precision = va_arg(args, int);
                format++;
            } else {
                while (*format >= '0' && *format <= '9') {
                    precision = precision * 10 + (*format++ - '0');
                }
            }
        }

        unsigned length = 0;
        if (*format == 'l') {
            length = 1;
            if (*++format == 'l') {
                length = 2;
                format++;
            }
        }

        switch (*format) {
        case 'd':
        case 'i':
            if (length == 2) {
                putint(va_arg(args, long long));
            } else if (length == 1) {
                putint(va_arg(args, long));
            } else {
                putint(va_arg(args, int));
            }
            break;

        case 'u':
            if (length == 2) {
                putuint(va_arg(args, unsigned long long), 10, false);
            } else if (length == 1) {
                putuint(va_arg(args, unsigned long), 10, false);
            } else {
                putuint(va_arg(args, unsigned int), 10, false);
            }
            break;

        case 'x':
        case 'X': {
            bool upper = *format == 'X';
            if (length == 2) {
                putuint(va_arg(args, unsigned long long), 16, upper);
            } else if (length == 1) {
                putuint(va_arg(args, unsigned long), 16, upper);
            } else {
                putuint(va_arg(args, unsigned int), 16, upper);
            }
            break;
        }

        case 'p':
            microkit_dbg_puts("0x");
            putuint((uintptr_t)va_arg(args, void *), 16, false);
            break;

        case 's': {
            const char *s = va_arg(args, const char *);
            if (!s) {
                s = "(null)";
            }
            if (precision < 0) {
                microkit_dbg_puts(s);
            } else {
                while (*s && precision-- > 0) {
                    microkit_dbg_putc(*s++);
                }
            }
            break;
        }

        case 'c':
            microkit_dbg_putc((char)va_arg(args, int));
            break;

        case '%':
            microkit_dbg_putc('%');
            break;

        default:
            microkit_dbg_putc('%');
            if (*format) {
                microkit_dbg_putc(*format);
            }
            break;
        }

        if (*format) {
            format++;
        }
    }

    va_end(args);
}

void tsldr_miscutil_load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr)
{
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        void *src = (char *)ehdr + phdr[i].p_offset;
        void *dest = (void *)(dest_vaddr + phdr[i].p_vaddr - ehdr->e_entry);

        tsldr_miscutil_memcpy(dest, src, phdr[i].p_filesz);

        if (phdr[i].p_memsz > phdr[i].p_filesz) {
            seL4_Word bss_size = phdr[i].p_memsz - phdr[i].p_filesz;
            tsldr_miscutil_memset((char *)dest + phdr[i].p_filesz, 0, bss_size);
        }
    }
}

void *tsldr_miscutil_find_section_from_elf(void *elf_base, char section[])
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)elf_base;
    Elf64_Shdr *sh_table = (Elf64_Shdr *)(elf_base + eh->e_shoff);
    Elf64_Shdr *shstr_sh = &sh_table[eh->e_shstrndx];

    const char *shstrtab = (const char *)(elf_base + shstr_sh->sh_offset);

    for (int i = 0; i < eh->e_shnum; ++i) {
        Elf64_Shdr *sh = &sh_table[i];
        if (sh->sh_name >= shstr_sh->sh_size) {
            continue;
        }
        const char *name = shstrtab + sh->sh_name;
        if (tsldr_miscutil_strcmp(name, section) == 0) {
            return (void *)sh;
        }
    }
    return (void *)NULL;
}

seL4_Word tsldr_miscutil_fetch_elf_section_with_vaddr(const void *elf_base,
                                                      uintptr_t vaddr,
                                                      seL4_Word *sh_size)
{
    const uint8_t *base = (const uint8_t *)elf_base;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + eh->e_shoff);

    for (uint16_t i = 0; i < eh->e_shnum; ++i) {
        seL4_Word start = sh[i].sh_addr;
        seL4_Word size = sh[i].sh_size;
        if (vaddr >= start && vaddr < start + size) {
            if (sh[i].sh_type == SHT_NOBITS) {
                break;
            }
            if (sh_size) {
                *sh_size = size;
            }
            return (seL4_Word)(elf_base + sh[i].sh_offset + (vaddr - start));
        }
    }
    return (seL4_Word)-1;
}
