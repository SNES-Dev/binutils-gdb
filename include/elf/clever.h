#ifndef _ELF_CLEVER_H
#define _ELF_CLEVER_H

#include "elf/reloc-macros.h"

START_RELOC_NUMBERS(elf_clever_reloc_type)
    RELOC_NUMBER(R_CLEVER_NONE, 0)
    RELOC_NUMBER(R_CLEVER_16, 1)
    RELOC_NUMBER(R_CLEVER_32, 2)
    RELOC_NUMBER(R_CLEVER_64, 3)
    RELOC_NUMBER(R_CLEVER_16_PCREL, 5)
    RELOC_NUMBER(R_CLEVER_32_PCREL, 6)
    RELOC_NUMBER(R_CLEVER_64_PCREL, 7)
    RELOC_NUMBER(R_CLEVER_SIMM, 8)
    RELOC_NUMBER(R_CLEVER_SIMM_PCREL, 9)
    RELOC_NUMBER(R_CLEVER_RELAX_LONG, 10)
    RELOC_NUMBER(R_CLEVER_RELAX_LONG_PCREL, 11)
    RELOC_NUMBER(R_CLEVER_RELAX_SHORT, 12)
    RELOC_NUMBER(R_CLEVER_RELAX_SHORT_PCREL, 13)
    RELOC_NUMBER(R_CLEVER_GOT, 16)
    RELOC_NUMBER(R_CLEVER_GOT_PCREL, 17)
    RELOC_NUMBER(R_CLEVER_PLT, 18)
    RELOC_NUMBER(R_CLEVER_PLT_PCREL, 19)
    RELOC_NUMBER(R_CLEVER_RELAX_GOT, 20)
    RELOC_NUMBER(R_CLEVER_RELAX_GOT_PCREL, 21)
    RELOC_NUMBER(R_CLEVER_RELAX_PLT, 22)
    RELOC_NUMBER(R_CLEVER_RELAX_PLT_PCREL, 23)
END_RELOC_NUMBERS(R_CLEVER_MAX)

#endif _ELF_CLEVER_H 