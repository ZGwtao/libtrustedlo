
#include <miscutils.h>
#include <stdarg.h>

void* tsldr_miscutil_memcpy(void *restrict dest, const void *restrict src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *s = src;

#ifdef __GNUC__

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define LS >>
#define RS <<
#else
#define LS <<
#define RS >>
#endif

	typedef uint32_t __attribute__((__may_alias__)) u32;
	uint32_t w, x;

	for (; (uintptr_t)s % 4 && n; n--) *d++ = *s++;

	if ((uintptr_t)d % 4 == 0) {
		for (; n>=16; s+=16, d+=16, n-=16) {
			*(u32 *)(d+0) = *(u32 *)(s+0);
			*(u32 *)(d+4) = *(u32 *)(s+4);
			*(u32 *)(d+8) = *(u32 *)(s+8);
			*(u32 *)(d+12) = *(u32 *)(s+12);
		}
		if (n&8) {
			*(u32 *)(d+0) = *(u32 *)(s+0);
			*(u32 *)(d+4) = *(u32 *)(s+4);
			d += 8; s += 8;
		}
		if (n&4) {
			*(u32 *)(d+0) = *(u32 *)(s+0);
			d += 4; s += 4;
		}
		if (n&2) {
			*d++ = *s++; *d++ = *s++;
		}
		if (n&1) {
			*d = *s;
		}
		return dest;
	}

	if (n >= 32) switch ((uintptr_t)d % 4) {
	case 1:
		w = *(u32 *)s;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		n -= 3;
		for (; n>=17; s+=16, d+=16, n-=16) {
			x = *(u32 *)(s+1);
			*(u32 *)(d+0) = (w LS 24) | (x RS 8);
			w = *(u32 *)(s+5);
			*(u32 *)(d+4) = (x LS 24) | (w RS 8);
			x = *(u32 *)(s+9);
			*(u32 *)(d+8) = (w LS 24) | (x RS 8);
			w = *(u32 *)(s+13);
			*(u32 *)(d+12) = (x LS 24) | (w RS 8);
		}
		break;
	case 2:
		w = *(u32 *)s;
		*d++ = *s++;
		*d++ = *s++;
		n -= 2;
		for (; n>=18; s+=16, d+=16, n-=16) {
			x = *(u32 *)(s+2);
			*(u32 *)(d+0) = (w LS 16) | (x RS 16);
			w = *(u32 *)(s+6);
			*(u32 *)(d+4) = (x LS 16) | (w RS 16);
			x = *(u32 *)(s+10);
			*(u32 *)(d+8) = (w LS 16) | (x RS 16);
			w = *(u32 *)(s+14);
			*(u32 *)(d+12) = (x LS 16) | (w RS 16);
		}
		break;
	case 3:
		w = *(u32 *)s;
		*d++ = *s++;
		n -= 1;
		for (; n>=19; s+=16, d+=16, n-=16) {
			x = *(u32 *)(s+3);
			*(u32 *)(d+0) = (w LS 8) | (x RS 24);
			w = *(u32 *)(s+7);
			*(u32 *)(d+4) = (x LS 8) | (w RS 24);
			x = *(u32 *)(s+11);
			*(u32 *)(d+8) = (w LS 8) | (x RS 24);
			w = *(u32 *)(s+15);
			*(u32 *)(d+12) = (x LS 8) | (w RS 24);
		}
		break;
	}
	if (n&16) {
		*d++ = *s++; *d++ = *s++; *d++ = *s++; *d++ = *s++;
		*d++ = *s++; *d++ = *s++; *d++ = *s++; *d++ = *s++;
		*d++ = *s++; *d++ = *s++; *d++ = *s++; *d++ = *s++;
		*d++ = *s++; *d++ = *s++; *d++ = *s++; *d++ = *s++;
	}
	if (n&8) {
		*d++ = *s++; *d++ = *s++; *d++ = *s++; *d++ = *s++;
		*d++ = *s++; *d++ = *s++; *d++ = *s++; *d++ = *s++;
	}
	if (n&4) {
		*d++ = *s++; *d++ = *s++; *d++ = *s++; *d++ = *s++;
	}
	if (n&2) {
		*d++ = *s++; *d++ = *s++;
	}
	if (n&1) {
		*d = *s;
	}
	return dest;
#endif

	for (; n; n--) *d++ = *s++;
	return dest;
}


void *tsldr_miscutil_memset(void *dest, int c, size_t n)
{
	unsigned char *s = dest;
	size_t k;

	/* Fill head and tail with minimal branching. Each
	 * conditional ensures that all the subsequently used
	 * offsets are well-defined and in the dest region. */

	if (!n) return dest;
	s[0] = c;
	s[n-1] = c;
	if (n <= 2) return dest;
	s[1] = c;
	s[2] = c;
	s[n-2] = c;
	s[n-3] = c;
	if (n <= 6) return dest;
	s[3] = c;
	s[n-4] = c;
	if (n <= 8) return dest;

	/* Advance pointer to align it at a 4-byte boundary,
	 * and truncate n to a multiple of 4. The previous code
	 * already took care of any head/tail that get cut off
	 * by the alignment. */

	k = -(uintptr_t)s & 3;
	s += k;
	n -= k;
	n &= -4;

#ifdef __GNUC__
	typedef uint32_t __attribute__((__may_alias__)) u32;
	typedef uint64_t __attribute__((__may_alias__)) u64;

	u32 c32 = ((u32)-1)/255 * (unsigned char)c;

	/* In preparation to copy 32 bytes at a time, aligned on
	 * an 8-byte bounary, fill head/tail up to 28 bytes each.
	 * As in the initial byte-based head/tail fill, each
	 * conditional below ensures that the subsequent offsets
	 * are valid (e.g. !(n<=24) implies n>=28). */

	*(u32 *)(s+0) = c32;
	*(u32 *)(s+n-4) = c32;
	if (n <= 8) return dest;
	*(u32 *)(s+4) = c32;
	*(u32 *)(s+8) = c32;
	*(u32 *)(s+n-12) = c32;
	*(u32 *)(s+n-8) = c32;
	if (n <= 24) return dest;
	*(u32 *)(s+12) = c32;
	*(u32 *)(s+16) = c32;
	*(u32 *)(s+20) = c32;
	*(u32 *)(s+24) = c32;
	*(u32 *)(s+n-28) = c32;
	*(u32 *)(s+n-24) = c32;
	*(u32 *)(s+n-20) = c32;
	*(u32 *)(s+n-16) = c32;

	/* Align to a multiple of 8 so we can fill 64 bits at a time,
	 * and avoid writing the same bytes twice as much as is
	 * practical without introducing additional branching. */

	k = 24 + ((uintptr_t)s & 4);
	s += k;
	n -= k;

	/* If this loop is reached, 28 tail bytes have already been
	 * filled, so any remainder when n drops below 32 can be
	 * safely ignored. */

	u64 c64 = c32 | ((u64)c32 << 32);
	for (; n >= 32; n-=32, s+=32) {
		*(u64 *)(s+0) = c64;
		*(u64 *)(s+8) = c64;
		*(u64 *)(s+16) = c64;
		*(u64 *)(s+24) = c64;
	}
#else
	/* Pure C fallback with no aliasing violations. */
	for (; n; n--, s++) *s = c;
#endif

	return dest;
}

int tsldr_miscutil_memcmp(const unsigned char* s1, const unsigned char* s2, int n)
{
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

int tsldr_miscutil_strcmp(const char* s1, const char* s2)
{
    const unsigned char* a = (const unsigned char*)s1;
    const unsigned char* b = (const unsigned char*)s2;

    int i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i]) {
            return (a[i] - b[i]);
        }
        i++;
    }
    return (a[i] - b[i]);
}


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

void putdecimal(uint8_t val)
{
    if (0 <= val && val <= 9) {
        putc('0' + val);
    } else {
        /* fallback, shouldn't really happen */
        puthex32(val);
    }
}

void tsldr_miscutil_dbg_print(const char *format, ...)
{
    va_list args;
    va_start(args, format);

    const char *ptr = format;

    while (*ptr != '\0') {
        if (*ptr == '%') {
            ptr++; // Move past '%'

            switch (*ptr) {
                case 's': {
                    // String
                    const char *str = va_arg(args, const char *);
                    if (str != 0) {
                        microkit_dbg_puts(str);
                    } else {
                        microkit_dbg_puts("(null)");
                    }
                    break;
                }
                case 'd': {
                    // Decimal
                    uint64_t val = va_arg(args, uint64_t);
                    putdecimal(val);
                    break;
                }
                case 'x': {
                    // Hexadecimal
                    uint64_t val = va_arg(args, uint64_t);
                    puthex64(val);
                    break;
                }
                case 'c': {
                    // Character
                    int c = va_arg(args, int); // char is promoted to int
                    microkit_dbg_putc((char)c);
                    break;
                }
                case '%': {
                    // Literal '%'
                    microkit_dbg_putc('%');
                    break;
                }
                default: {
                    // Unsupported format specifier, print it literally
                    microkit_dbg_putc('%');
                    microkit_dbg_putc(*ptr);
                    break;
                }
            }
            ptr++; // Move past format specifier
        } else {
            // Regular character
            microkit_dbg_putc(*ptr);
            ptr++;
        }
    }

    va_end(args);
}


void tsldr_miscutil_load_elf(void *dest_vaddr, const Elf64_Ehdr *ehdr)
{
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char*)ehdr + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        void *src = (char*)ehdr + phdr[i].p_offset;
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
        if (sh->sh_name >= shstr_sh->sh_size) continue;
        const char *name = shstrtab + sh->sh_name;
        if (tsldr_miscutil_strcmp(name, section) == 0) {
            return (void *)sh;
        }
    }
    return (void *)NULL;
}


seL4_Word tsldr_miscutil_fetch_elf_section_with_vaddr(const void *elf_base, uintptr_t vaddr, seL4_Word *sh_size)
{
    const uint8_t    *base = (const uint8_t *)elf_base;
    const Elf64_Ehdr *eh   = (const Elf64_Ehdr *)base;
    const Elf64_Shdr *sh   = (const Elf64_Shdr *)(base + eh->e_shoff);

    for (uint16_t i = 0; i < eh->e_shnum; ++i) {
        seL4_Word start = sh[i].sh_addr;
        seL4_Word size  = sh[i].sh_size;
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

