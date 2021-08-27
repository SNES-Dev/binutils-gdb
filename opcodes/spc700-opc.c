/*

const struct spc700_opcode spc700_opcodes[] = {

}

definer struct spc700_opcode i include/opcode/spc700.h
denne headeren vil da inkluderes av gas mens den linker mot libopcode.
gas finner og bruker spc700_opcodes[] via libopcode og headeren

*/

#include <stdio.h>
#include "libiberty.h"
#include "symcat.h"
#include "opcode/spc700.h"

/*
Note: There's a slightly unfortunate naming scheme going on here. Anyone have suggestions for a better naming scheme? If so, go nuts.
The possible confusion is as follows regarding the definition of "indirect":
SPC700_Argtype_X_Indirect means to treat X as a pointer, but SPC700_Argtype_DP_Plus_X_Indirect means to treat DP+X as a double-pointer, "**(DP+X)"
Similarly, SPC700_Argtype_DP_Indirect_Plus_Y treats DP as a double-pointer, looks up the pointer at dpbase+dp, then adds Y to the looked up pointer and fetches the final value from *(*(dpbase+dp)+Y).
In other words, any indirect addressing modes that includes DP involves pointer-pointers. Otherwise, "indirect" means "treat this register as a single-pointer with lookup instead of a direct value".
Another way of thinking about it is that DP is usually a pointer, so "indirect" means treat it as a pointer-pointer. While X and Y are usually values, so "indirect" then means treat them as pointers.
You basically go one abstraction/indirection up.

Also, the indirect DP pointer-pointer addressing modes use square brackets [] in its syntax. Look at the format strings at the rightmost column in the table.
Indirect X and Y addressing modes uses parantheses () to indicate pointers. A plus after the parantheses means autoincrement.
*/

struct spc700_opcode spc700_opcodes[] = {
  {"MOV", 0xE8, 2, 2, 1, {SPC700_Argtype_A,                   SPC700_Argtype_Immediate,           SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov A,%s"    },
  {"MOV", 0xE6, 1, 2, 0, {SPC700_Argtype_A,                   SPC700_Argtype_X_Indirect,          SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Move,   "mov A,(X)"   },
  {"MOV", 0xBF, 1, 2, 0, {SPC700_Argtype_A,                   SPC700_Argtype_X_Indirect_AutoIncr, SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Move,   "mov A,(X)+"  },
  {"MOV", 0xE4, 2, 2, 1, {SPC700_Argtype_A,                   SPC700_Argtype_DP,                  SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov A,%s"    },
  {"MOV", 0xF4, 2, 2, 1, {SPC700_Argtype_A,                   SPC700_Argtype_DP_Plus_X,           SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov A,%s+X"  },
  {"MOV", 0xE5, 3, 2, 1, {SPC700_Argtype_A,                   SPC700_Argtype_AbsAddr,             SPC700_Argtype_None}, {0x00000000,0x00FFFF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov A,%s"    },
  {"MOV", 0xF5, 3, 2, 1, {SPC700_Argtype_A,                   SPC700_Argtype_AbsAddr_Plus_X,      SPC700_Argtype_None}, {0x00000000,0x00FFFF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov A,%s+X"  },
  {"MOV", 0xF6, 3, 2, 1, {SPC700_Argtype_A,                   SPC700_Argtype_AbsAddr_Plus_Y,      SPC700_Argtype_None}, {0x00000000,0x00FFFF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov A,%s+Y"  },
  {"MOV", 0xE7, 2, 2, 1, {SPC700_Argtype_A,                   SPC700_Argtype_DP_Plus_X_Indirect,  SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov A,[%s+X]"},
  {"MOV", 0xF7, 2, 2, 1, {SPC700_Argtype_A,                   SPC700_Argtype_DP_Indirect_Plus_Y,  SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov A,[%s]+Y"},
  {"MOV", 0xCD, 2, 2, 1, {SPC700_Argtype_X,                   SPC700_Argtype_Immediate,           SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov X,%s"    },
  {"MOV", 0xF8, 2, 2, 1, {SPC700_Argtype_X,                   SPC700_Argtype_DP,                  SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov X,%s"    },
  {"MOV", 0xF9, 2, 2, 1, {SPC700_Argtype_X,                   SPC700_Argtype_DP_Plus_Y,           SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov X,%s+Y"  },
  {"MOV", 0xE9, 3, 2, 1, {SPC700_Argtype_X,                   SPC700_Argtype_AbsAddr,             SPC700_Argtype_None}, {0x00000000,0x00FFFF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov X,%s"    },
  {"MOV", 0x8D, 2, 2, 1, {SPC700_Argtype_Y,                   SPC700_Argtype_Immediate,           SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov Y,%s"    },
  {"MOV", 0xEB, 2, 2, 1, {SPC700_Argtype_Y,                   SPC700_Argtype_DP,                  SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov Y,%s"    },
  {"MOV", 0xFB, 2, 2, 1, {SPC700_Argtype_Y,                   SPC700_Argtype_DP_Plus_X,           SPC700_Argtype_None}, {0x00000000,0x0000FF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov Y,%s+X"  },
  {"MOV", 0xEC, 3, 2, 1, {SPC700_Argtype_Y,                   SPC700_Argtype_AbsAddr,             SPC700_Argtype_None}, {0x00000000,0x00FFFF00,0x00000000}, {0x00,0x08,0x00}, InsnGroup_Move,   "mov Y,%s"    },

  {"MOV", 0xC6, 1, 2, 0, {SPC700_Argtype_X_Indirect,          SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Move,   "mov (X),A"   },
  {"MOV", 0xAF, 1, 2, 0, {SPC700_Argtype_X_Indirect_AutoIncr, SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Move,   "mov (X)+,A"  },
  {"MOV", 0xC4, 2, 2, 1, {SPC700_Argtype_DP,                  SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x0000FF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s,A"    },
  {"MOV", 0xD4, 2, 2, 1, {SPC700_Argtype_DP_Plus_X,           SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x0000FF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s+X,A"  },
  {"MOV", 0xC5, 3, 2, 1, {SPC700_Argtype_AbsAddr,             SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x00FFFF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s,A"    },
  {"MOV", 0xD5, 3, 2, 1, {SPC700_Argtype_AbsAddr_Plus_X,      SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x00FFFF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s+X,A"  },
  {"MOV", 0xD6, 3, 2, 1, {SPC700_Argtype_AbsAddr_Plus_Y,      SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x00FFFF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s+Y,A"  },
  {"MOV", 0xC7, 2, 2, 1, {SPC700_Argtype_DP_Plus_X_Indirect,  SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x0000FF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov [%s+X],A"},
  {"MOV", 0xD7, 2, 2, 1, {SPC700_Argtype_DP_Indirect_Plus_Y,  SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x0000FF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov [%s]+Y,A"},
  {"MOV", 0xD8, 2, 2, 1, {SPC700_Argtype_DP,                  SPC700_Argtype_X,                   SPC700_Argtype_None}, {0x0000FF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s,X"    },
  {"MOV", 0xD9, 2, 2, 1, {SPC700_Argtype_DP_Plus_Y,           SPC700_Argtype_X,                   SPC700_Argtype_None}, {0x0000FF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s+Y,X"  },
  {"MOV", 0xC9, 3, 2, 1, {SPC700_Argtype_AbsAddr,             SPC700_Argtype_X,                   SPC700_Argtype_None}, {0x00FFFF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s,X"    },
  {"MOV", 0xCB, 2, 2, 1, {SPC700_Argtype_DP,                  SPC700_Argtype_Y,                   SPC700_Argtype_None}, {0x0000FF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s,Y"    },
  {"MOV", 0xDB, 2, 2, 1, {SPC700_Argtype_DP_Plus_X,           SPC700_Argtype_Y,                   SPC700_Argtype_None}, {0x0000FF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s+X,Y"  },
  {"MOV", 0xCC, 3, 2, 1, {SPC700_Argtype_AbsAddr,             SPC700_Argtype_Y,                   SPC700_Argtype_None}, {0x00FFFF00,0x00000000,0x00000000}, {0x08,0x00,0x00}, InsnGroup_Move,   "mov %s,Y"    },

  {"MOV", 0x7D, 1, 2, 0, {SPC700_Argtype_A,                   SPC700_Argtype_X,                   SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Move,   "mov A,X"     },
  {"MOV", 0xDD, 1, 2, 0, {SPC700_Argtype_A,                   SPC700_Argtype_Y,                   SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Move,   "mov A,Y"     },
  {"MOV", 0x5D, 1, 2, 0, {SPC700_Argtype_X,                   SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Move,   "mov X,A"     },
  {"MOV", 0xFD, 1, 2, 0, {SPC700_Argtype_Y,                   SPC700_Argtype_A,                   SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Move,   "mov Y,A"     },
  {"MOV", 0x9D, 1, 2, 0, {SPC700_Argtype_X,                   SPC700_Argtype_SP,                  SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Stack,  "mov X,SP"    },
  {"MOV", 0xBD, 1, 2, 0, {SPC700_Argtype_SP,                  SPC700_Argtype_X,                   SPC700_Argtype_None}, {0x00000000,0x00000000,0x00000000}, {0x00,0x00,0x00}, InsnGroup_Stack,  "mov SP,X"    },
  {"MOV", 0xFA, 3, 2, 2, {SPC700_Argtype_DP,                  SPC700_Argtype_DP,                  SPC700_Argtype_None}, {0x0000FF00,0x00FF0000,0x00000000}, {0x08,0x10,0x00}, InsnGroup_Move,   "mov %s,%s"   },
  {"MOV", 0x8F, 3, 2, 2, {SPC700_Argtype_DP,                  SPC700_Argtype_Immediate,           SPC700_Argtype_None}, {0x0000FF00,0x00FF0000,0x00000000}, {0x08,0x10,0x00}, InsnGroup_Move,   "mov %s,%s"   }
};



const unsigned int spc700_opcode_table_len = SPC700_OPCODE_TABLE_SIZE;
