/* CR16 ELF support for BFD.
   Copyright (C) 2007-2021 Free Software Foundation, Inc.
   Contributed by Connor Horman.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _ELF_WDC65816_H
#define _ELF_WDC65816_H

#include "elf/reloc-macros.h"

START_RELOC_NUMBERS(elf_wdc65816_reloc_type)
    RELOC_NUMBER (R_WDC65816_NONE,           0)
    RELOC_NUMBER (R_WDC65816_ABS24,          1)
    RELOC_NUMBER (R_WDC65816_ABS16,          2)
    RELOC_NUMBER (R_WDC65816_REL8 ,          3)
    RELOC_NUMBER (R_WDC65816_REL16,          4)
    RELOC_NUMBER (R_WDC65816_BANK ,          5)
    RELOC_NUMBER (R_WDC65816_ABS8 ,          6)
    RELOC_NUMBER (R_WDC65816_DIR  ,          7)
END_RELOC_NUMBERS(R_WDC65816_MAX)

#endif /* _ELF_WDC65816_H */