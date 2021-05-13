/* This file is tc-wasm32.h.
   Copyright (C) 2017-2021 Free Software Foundation, Inc.

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */
#define TC_W65_H

#define TARGET_FORMAT "elf32-w65"
#define TARGET_ARCH bfd_arch_w65
#define TARGET_MACH 0

#define TARGET_BYTES_BIG_ENDIAN                          0
#define md_number_to_chars    number_to_chars_littleendian

#define tc_comment_chars w65_comment_chars

extern const char w65_comment_chars[];

#define WORKING_DOT_WORD