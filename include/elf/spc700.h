/* SPC700 ELF support for BFD.
   Copyright (C) 2007-2018 Free Software Foundation, Inc.
   Contributed by M R Swami Reddy.

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

#ifndef _ELF_SPC700_H
#define _ELF_SPC700_H

#include "elf/reloc-macros.h"

/* Creating indices for reloc_map_index array.  */
START_RELOC_NUMBERS(elf_spc700_reloc_type)
  RELOC_NUMBER (R_SPC700_NONE,            0)
  RELOC_NUMBER (R_SPC700_NUM8,            1)
  RELOC_NUMBER (R_SPC700_ABS,             2)
  RELOC_NUMBER (R_SPC700_ABS24,           3)
  RELOC_NUMBER (R_SPC700_IMM4,            4)
  RELOC_NUMBER (R_SPC700_IMM8,            5)
  RELOC_NUMBER (R_SPC700_IMM16,           6)
  RELOC_NUMBER (R_SPC700_DISP4,           7)
  RELOC_NUMBER (R_SPC700_DISP8,           8)
  RELOC_NUMBER (R_SPC700_DISP16,          9)
END_RELOC_NUMBERS(R_SPC700_MAX)

#endif /* _ELF_SPC700_H */
