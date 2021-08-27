/*
//extern int print_insn_spc700		(bfd_vma, disassemble_info *);
//sjekk dis-asm.h og disassemble.h
//void print_spc700_disassembler_options(void) (disassemble.c)

disassemble.c har også
void disassemble_init_for_target (struct disassemble_info * info)
som også kan brukes for å initialisere disassembleren

struct disassemble_info fra include/opcodes/dis-asm.h

typedef struct disassemble_info
{
  fprintf_ftype fprintf_func;
  void *stream;
  void *application_data;
  enum bfd_flavour flavour;
  enum bfd_architecture arch;
  unsigned long mach;
  enum bfd_endian endian;
  enum bfd_endian endian_code;
  void *insn_sets;
  asection *section;
  asymbol **symbols;
  int num_symbols;
  asymbol **symtab;
  int symtab_pos;
  int symtab_size;
  unsigned long flags;
  void *private_data;

  int (*read_memory_func)
    (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length,
     struct disassemble_info *dinfo);

  void (*memory_error_func)
    (int status, bfd_vma memaddr, struct disassemble_info *dinfo);

  void (*print_address_func)
    (bfd_vma addr, struct disassemble_info *dinfo);

  int (* symbol_at_address_func)
    (bfd_vma addr, struct disassemble_info *dinfo);

  bfd_boolean (* symbol_is_valid)
    (asymbol *, struct disassemble_info *dinfo);

  bfd_byte *buffer;
  bfd_vma buffer_vma;
  size_t buffer_length;
  int bytes_per_line;
  int bytes_per_chunk;
  enum bfd_endian display_endian;
  unsigned int octets_per_byte;
  unsigned int skip_zeroes;
  unsigned int skip_zeroes_at_end;

  bfd_boolean disassembler_needs_relocs;

  // Results from instruction decoders.  Set these.

  char insn_info_valid;
  char branch_delay_insns;
  char data_size;
  enum dis_insn_type insn_type;
  bfd_vma target;
  bfd_vma target2;
  const char *disassembler_options;
  bfd_vma stop_vma;

} disassemble_info;
*/

/*
Use these macros to convert words and dwords to the correct endianess

bfd_h_put_64
bfd_h_put_32
bfd_h_put_16
bfd_h_put_8
bfd_h_put_signed_64
bfd_h_put_signed_32
bfd_h_put_signed_16
bfd_h_put_signed_8
bfd_h_get_64
bfd_h_get_32
bfd_h_get_16
bfd_h_get_8
bfd_h_get_signed_64
bfd_h_get_signed_32
bfd_h_get_signed_16
bfd_h_get_signed_8

*/

#include "sysdep.h"
#include <assert.h>
#include "disassemble.h"
#include "opcode/spc700.h"
#include "libiberty.h"

typedef enum spc700_optype {
  SPC700_Optype_Address_Number,
  SPC700_Optype_Immediate_Number,
  SPC700_Optype_Address_Symbol,
  SPC700_Optype_Immediate_Symbol
} spc700_optype;


static int get_operand(char* buf, int buflen, bfd_vma address, struct disassemble_info* info, spc700_opcode* insn, int argindex){
  int status;
  uint32_t imm;
  uint32_t mem_rel;
  uint32_t mem_dp;
  uint32_t mem_abs;
  uint32_t mem_tcall;
  uint32_t mem_pcall;
  uint32_t data = 0;
  uint8_t buffer[3];

  memset(buf, 0, buflen);

  //bruk tabellen for å finne ut antall bytes vi må lese
  status = info->read_memory_func(address, buffer, insn->size, info);
  if(status){
    return status;
  }

  switch(insn->size){
    case 1:
    data = buffer[0];
    break;
    case 2:
    data = buffer[0]|(buffer[1]<<8);
    break;
    case 3:
    data = buffer[0]|(buffer[1]<<8)|(buffer[2]<<16);
    break;
  }
  /* Note: when disassembling, we assume that the CPU direct page flag is 0, so that DP=!0x0000
    TODO: lookup info->symbols or info->symtab to replace values with symbols */
  switch(insn->argtypes[argindex]){
    case SPC700_Argtype_Immediate:{
      imm = (data&insn->argmasks[argindex])>>insn->argshifts[argindex];
      snprintf(buf, buflen, "#%d", imm);
    }
    break;
    case SPC700_Argtype_DP:
    case SPC700_Argtype_DP_Plus_X:
    case SPC700_Argtype_DP_Plus_Y:
    case SPC700_Argtype_DP_Plus_X_Indirect:
    case SPC700_Argtype_DP_Indirect_Plus_Y:
    {
      mem_dp = (data&insn->argmasks[argindex])>>insn->argshifts[argindex];
      snprintf(buf, buflen, "0x%02X", mem_dp);
    }
    break;
    case SPC700_Argtype_AbsAddr:
    case SPC700_Argtype_AbsAddr_Plus_X:
    case SPC700_Argtype_AbsAddr_Plus_Y:{
      mem_abs = (data&insn->argmasks[argindex])>>insn->argshifts[argindex];
      snprintf(buf, buflen, "!0x%04X", mem_abs);
    }
    break;
    case SPC700_Argtype_PcRelAddr:{
      mem_rel = (int)address + (int8_t)((data&insn->argmasks[argindex])>>insn->argshifts[argindex]);
      snprintf(buf, buflen, "!0x%04X", mem_rel);
    }
    break;
    case SPC700_Argtype_PCallAddr:{
      mem_pcall = (data&insn->argmasks[argindex])>>insn->argshifts[argindex];
      snprintf(buf, buflen, "#%d", mem_pcall);
    }
    break;
    case SPC700_Argtype_TCallAddr:{
      mem_tcall = (data&insn->argmasks[argindex])>>insn->argshifts[argindex];
      snprintf(buf, buflen, "#%X", mem_tcall);
    }
    break;
    default:
    assert(!"invalid operand type in get_operand() !!");
    abort();
  }
  return 0;
}

static int is_argument_implicit(spc700_opcode* insn, int idx){
  return  ((insn->argtypes[i] == SPC700_Argtype_A) ||
          (insn->argtypes[i] == SPC700_Argtype_X) ||
          (insn->argtypes[i] == SPC700_Argtype_Y) ||
          (insn->argtypes[i] == SPC700_Argtype_SP) ||
          (insn->argtypes[i] == SPC700_Argtype_YA) ||
          (insn->argtypes[i] == SPC700_Argtype_X_Indirect) ||
          (insn->argtypes[i] == SPC700_Argtype_Y_Indirect) ||
          (insn->argtypes[i] == SPC700_Argtype_X_Indirect_AutoIncr));
}

int print_insn_spc700(bfd_vma address, struct disassemble_info* info){
  bfd_byte opcode;
  spc700_opcode* insn;
  int status;
  unsigned int i,j,argidx;
  char args[8][3] = {0};
  char insn_line[256];

  status = info->read_memory_func(address, &opcode, 1, info);
  if(status){
    info->memory_error_func(status, address, info);
    return 0;
  }

  /* TODO:  The SPC700 actually has exactly 256 different instructions.
            If we in the future sort the table, we can use the opcode directly for lookup.
            Which means O(1) lookup instead of O(n) ! */
  for(i = 0; i < spc700_opcode_table_len; i++){
    if(spc700_opcodes[i].opcode == opcode){
      insn = &spc700_opcodes[i];
      break;
    }
  }

  /* Note:  This sanity check is only done currently because the instruction table is incomplete.
            When the table is eventually complete, all of the 256 values will be covered and
            it will be impossible to get a mismatch/lookup failure. */
  if(i == spc700_opcode_table_len){
    /* unknown opcode, treat as raw byte */
    info->fprintf_func(info->stream,".byte %d",opcode);
    return 1;
  }

  /* if we get here, we have a legal opcode */

  /* parse our explicit operands if we have some */
  for(argidx = 0,j=0; argidx < insn->numargs; argidx++){
    if(is_argument_implicit(insn, argidx) || insn->argtypes[i] == SPC700_Argtype_None) continue;
    if(0 != (status = get_operand(args[j], 8, address, info, insn, argidx))){
      info->memory_error_func(status, address, info);
    }
    j++;
  }

  /* implied instructions are encoded directly inside the 'insn->args' format string,
  so only explicit arguments (constant addresses and immediates) are passed as arguments to snprintf.
  For example, case 0 below handles cases with no explicit arguments, such as when 'insn->args' is "mov A,(X)",
  and case 1 handles cases with a single explicit argument, such as when 'insn->args' is "mov A,#0xff", "mov 0x0,A" or "mov !0xFC81+X, A".
  */
  switch(insn->numargs_noimplied){
    case 0:
      snprintf(insn_line, 256, "%s", insn->args);
      break;
    case 1:
      snprintf(insn_line, 256, insn->args, args[0]);
      break;
    case 2:
      snprintf(insn_line, 256, insn->args, args[0], args[1]);
      break;
    case 3:
      snprintf(insn_line, 256, insn->args, args[0], args[1], args[2]);
      break;
  }
  info->fprintf_func (info->stream,"%s", insn_line);

  /* consumed 'size' bytes */
  return insn->size;
}
