#include <stdint.h>

//todo: add PSW to table
typedef enum spc700_argtype {
  SPC700_Argtype_None = 0,
  SPC700_Argtype_A,                        //A
  SPC700_Argtype_X,                        //X
  SPC700_Argtype_Y,                        //Y
  SPC700_Argtype_YA,                       //YA
  SPC700_Argtype_SP,                       //SP
  SPC700_Argtype_PSW,                      //PSW
  SPC700_Argtype_Immediate,                //#435
  SPC700_Argtype_DP,                       //dp
  SPC700_Argtype_AbsAddr,                  //!0x56FF
  SPC700_Argtype_PcRelAddr,                //PC relative address/jump/call
  SPC700_Argtype_PCallAddr,                //PCALL upage
  SPC700_Argtype_TCallAddr,                //TCALL n
  SPC700_Argtype_X_Indirect,               //X (dereferenced as an address)
  SPC700_Argtype_Y_Indirect,               //Y (dereferenced as an address)
  SPC700_Argtype_X_Indirect_AutoIncr,      //X (dereferenced as an address) and incremented after
  SPC700_Argtype_DP_Plus_X,                //(dp+X) (dereferenced as an address)
  SPC700_Argtype_DP_Plus_Y,                //(dp+Y) (dereferenced as an address)
  SPC700_Argtype_AbsAddr_Plus_X,           //(!0x00FF+X) (dereferenced as an address)
  SPC700_Argtype_AbsAddr_Plus_Y,           //(!0x00FF+Y) (dereferenced as an address)
  SPC700_Argtype_DP_Plus_X_Indirect,       //((dp+X)) (dp+X is an absolute double-pointer)
  SPC700_Argtype_DP_Indirect_Plus_Y,       //((dp)+Y) (dp is an absolute double-pointer, where the looked up pointer gets added to Y)
  SPC700_Argtype_JMP_ABS_Plus_X_Indirect   //JMP [!abs+X]
} spc700_argtype;

typedef enum spc700_insngroup {
  InsnGroup_Move, /* different MOV insns */
  InsnGroup_Arithmetic, /* sbc, adc, and, or, eor, mul, div, asl, lsr, rol, ror .. */
  InsnGroup_Cmp,  /* cmp, cmpw */
  InsnGroup_Branch, /* BRA, Bxx */
  InsnGroup_Subroutine, /* CALL, PCALL, TCALL */
  InsnGroup_Stack, /* push, pop */
  InsnGroup_Other /* SET1, CLR1, EOR1, NOT1, CLRC, CLRP, EI, DI, NOP, SLEEP, etc .. */
} spc700_insngroup;

typedef struct spc700_opcode
{
  /* The opcode name.  */
  const char *name;
  /* The opcode itself.  */
  unsigned long opcode;
  /* The pseudo-size of the instruction(in bytes).  Used to determine
     number of bytes necessary to disassemble the instruction.  */
  unsigned int size;
  /* number of arguments (including implied arguments) */
  unsigned int numargs;
  /* number of arguments not counting implied arguments (actual number of arguments to read after the insn) */
  unsigned int numargs_noimplied;
  /* The arguments/operands with their types. We can have up to 3 operands, but only 'numargs' indices are defined */
  spc700_argtype argtypes[3];
  /* masks to extract each argument */
  uint32_t argmasks[3];
  /* how much to shift down each argument after masking*/
  uint32_t argshifts[3];

  /* A general category the insns belongs to */
  spc700_insngroup category;

  /* All of the arguments (without the opcode) as a human-readable string  */
  const char *args;
} spc700_opcode;

extern struct spc700_opcode spc700_opcodes[];
extern const unsigned int spc700_opcode_table_len;
#define SPC700_OPCODE_TABLE_SIZE (sizeof(spc700_opcodes)/sizeof(spc700_opcodes[0]))
