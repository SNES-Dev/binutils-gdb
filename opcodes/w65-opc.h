
/* w65-opc.h -- Functions for opcodes for the w65 processor.
   Copyright (C) 2007-2021 Free Software Foundation, Inc.
   Contributed by Connor Horman

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */
#ifndef W65_OPC_H
#define W65_OPC_H

#include "opcode/w65.h"

int length_by_addr_mode(w65_addr_mode md,w65_prg_flags flg);

#endif /* W65_OPC_H */