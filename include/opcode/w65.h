/* cr16.h -- Header file for CR16 opcode and register tables.
   Copyright (C) 2007-2021 Free Software Foundation, Inc.
   Contributed by Connor Horman

   This file is part of GAS, GDB and the GNU binutils.

   GAS, GDB, and GNU binutils is free software; you can redistribute it
   and/or modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 3, or (at your
   option) any later version.

   GAS, GDB, and GNU binutils are distributed in the hope that they will be
   useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _W65_H
#define _W65_H


typedef enum{
   /* ABSOLUTE addressing mode */
   ABS,
   /* A(ccumulator) addressing mode */
   ACC,
   /* D,ASB8 addressing mode */
   DIRECT,
   /* Implied addressing mode */
   IMPLIED,
   /* LONG addressing mode */
   LONG,
   /* rel8 addressing mode */
   REL8,
   /* rel16 addressing mode */
   REL16,
   /* src,dst addressing mode */
   SRC_DST,
   /* STACK,8 addressing mode */
   STACK,
   /* imm operand, for LDA imm */
   IMMA,
   /* imm operand, for LDX imm, or LDY imm */
   IMMX,
   /* 8-bit immediate, used by BRK, COP, WDM, SEP, and REP */
   IMM8,
   /* 16-bit immediate, used by PEA and PER */
   IMM16, 

   // INDIRECT to address mode: (addr)
   INDIRECT = 0x1000,
   // Long Indirect to address mode: [addr]
   INDIRECT_LONG = 0x2000,
   // Indirect to address mode, indexed by X: (addr,X)
   INDIRECT_X = 0x3000,
   // Indirect to address mode, indexed by Y: (addr,Y)
   INDIRECT_Y = 0x4000,
   // Address mode, indexed by X: addr,X
   INDEXED_X = 0x100,
   // Address mode, indexed by Y: addr,Y
   INDEXED_Y = 0x200,
}w65_addr_mode;

typedef enum{
    C = 0x01,
    Z = 0x02,
    I = 0x04,
    D = 0x08,
    X = 0x10,
    M = 0x20,
    V = 0x40,
    N = 0x80,

    E = 0x100 // Not actually a flag
}w65_prg_flags;

typedef struct{
   const char* mnemonic;
   unsigned char opc;
   w65_addr_mode oprs;
}w65_insn;

typedef struct{
    const char* name;
    unsigned char mode_and_number;
}w65_trap_entry;

#endif /* _W65_H */