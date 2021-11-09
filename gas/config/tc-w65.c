#include "config.h"

#include <limits.h>
#include <stdlib.h>

#include "as.h"
#include "safe-ctype.h"
#include "opcode/w65.h"

#ifdef OBJ_ELF
#include "elf/w65.h"
#include "dwarf2dbg.h"
#endif

#ifdef OBJ_COFF
#include "coff/w65.h"
#endif

#define WORD_SHIFT  16

#define streq(a, b)           (strcmp (a, b) == 0)


extern const w65_insn w65_insn_tab[];

/* Array to hold an instruction encoding.  */
long output_opcode[2];

/* Nonzero means a relocatable symbol.  */
int relocatable;

/* A copy of the original instruction (used in error messages).  */
char ins_parse[256];

/* The current processed argument number.  */
int cur_arg_num;

const char w65_comment_chars[] = ";";

/* Generic assembler global variables which must be defined by all targets.  */

/* Characters which always start a comment.  */
const char comment_chars[] = ";";

/* Characters which start a comment at the beginning of a line.  */
const char line_comment_chars[] = ";";

/* This array holds machine specific line separator characters.  */
const char line_separator_chars[] = "";

/* Chars that can be used to separate mant from exp in floating point nums.  */
const char EXP_CHARS[] = "eE";

/* Chars that mean this number is a floating point constant as in 0f12.456  */
const char FLT_CHARS[] = "f";

const char *md_shortopts = "";

static w65_prg_flags w65_flg;

static htab_t insn_htab;

struct option md_longopts[] =
{
  {NULL, no_argument, NULL, 0}
};
size_t md_longopts_size = sizeof (md_longopts);


static void w65_set_flg(int flags){
  w65_flg |= flags;
}

static void w65_reset_flg(int flags){
  w65_flg &= ~flags;
}

const pseudo_typeS md_pseudo_table[] = {
  {"acc8",w65_set_flg,M},
  {"idx8",w65_set_flg,X},
  {"acc16",w65_reset_flg,M},
  {"idx16",w65_reset_flg,X},
  {0, 0, 0}
};

int
md_parse_option (int c ATTRIBUTE_UNUSED, const char *arg ATTRIBUTE_UNUSED)
{
  return 0;
}

void
md_show_usage (FILE *stream ATTRIBUTE_UNUSED)
{
  return;
}

void md_begin(void)
{
  insn_htab = str_htab_create();
  int i = 0;
  while (w65_insn_tab[i].mnemonic != NULL)
    {
      const char *mnemonic = w65_insn_tab[i].mnemonic;

      if (str_hash_insert (insn_htab,mnemonic, w65_insn_tab + i, 0))
	as_fatal (_("duplicate %s"), mnemonic);

      /* Insert unique names into hash table.  The w65 instruction set
	 has many identical opcode names that have different opcodes based
	 on the operands.  This hash table then provides a quick index to
	 the first opcode with a particular name in the opcode table.  */
      do
	{
	  ++i;
	}
      while (w65_insn_tab[i].mnemonic != NULL
	     && streq (w65_insn_tab[i].mnemonic, mnemonic));
    }

}
const char *
md_atof (int type, char *litP, int *sizeP)
{
  return ieee_md_atof (type, litP, sizeP, 0);
}

symbolS *
md_undefined_symbol (char *name ATTRIBUTE_UNUSED){
  return NULL;
}

void
md_operand (expressionS * exp ATTRIBUTE_UNUSED){
  // TODO: Do I need to do anything here
}

valueT
md_section_align (segT seg ATTRIBUTE_UNUSED, valueT val){
  return val;
}

long
md_pcrel_from (fixS *fixP)
{
  return fixP->fx_size + fixP->fx_where + fixP->fx_frag->fr_address;
}

static void
reset_vars (char *op)
{
  cur_arg_num = relocatable = 0;
  memset (& output_opcode, '\0', sizeof (output_opcode));

  /* Save a copy of the original OP (used in error messages).  */
  strncpy (ins_parse, op, sizeof ins_parse - 1);
  ins_parse [sizeof ins_parse - 1] = 0;
}



struct w65_operand{
  w65_addr_mode md;
  expressionS expr;
  bfd_boolean bank;
};

static void parse_tail(struct w65_operand* op, char* tail, int x_flag, int y_flag){
  if(*tail==',')
    tail++;
  while(*tail&&ISSPACE(*tail))tail++;
  if(*tail=='%')
    tail++;
  while(*tail&&ISSPACE(*tail))tail++;
  switch(*tail){
    case 'D':
      op->md |= DIRECT;
      break;
    case 'X':
      op->md |= x_flag;
      break;
    case 'Y':
      op->md |= y_flag;
    
  }
}

static struct w65_operand
w65_op_from_param(char *param){
   struct w65_operand op = {.md = 0};
  input_line_pointer = param;
  SKIP_ALL_WHITESPACE();
  switch(*input_line_pointer){
    case '[':
      {
        op.md |= INDIRECT_LONG;
        char *look = ++input_line_pointer;
        while(*look&&*look!=']')
          look++;
        if(!*look)
          as_bad(_("Invalid Operand: %s"),param);
        *look = '\0';
        look++;
        expression(&op.expr);
        if(*input_line_pointer){
          SKIP_ALL_WHITESPACE();
          parse_tail(&op,input_line_pointer,INDIRECT_X,INDIRECT_Y);
        }
        if(*look){
          parse_tail(&op,look, INDEXED_X,INDEXED_Y);
        }
      }
    break;
    case '(':
      {
        op.md |= INDIRECT;
        char *look = ++input_line_pointer;
        while(*look&&*look!=')')
          look++;
        if(!*look)
          as_bad(_("Invalid Operand: %s"),param);
        *look = '\0';
        look++;
        expression(&op.expr);
        if(*input_line_pointer){
          SKIP_ALL_WHITESPACE();
          parse_tail(&op,input_line_pointer,INDIRECT_X,INDIRECT_Y);
        }
        if(*look){
          parse_tail(&op,look, INDEXED_X,INDEXED_Y);
        }
      }
    break;
    case '^':
      op.bank = true;
      input_line_pointer++;
      expression(&op.expr);
    break;
    case '#':
      op.md = IMM16;
      input_line_pointer++;
      __attribute__((fallthrough));
    default:
      expression(&op.expr);
      SKIP_ALL_WHITESPACE();
      if(*input_line_pointer)
        parse_tail(&op,input_line_pointer, INDEXED_X,INDEXED_Y);
    break;
  }

  
  //  while(ISSPACE(*param))param++;
  //  if(!*param)
  //   op.md = IMPLIED;
  //  else if(*param=='['){
  //    param++;
  //    char *look = param;
  //    while(*look&&*look!=']')
  //     look++;
  //    if(!*look)
  //       as_bad(_("Invalid operand: %s"),--param);
  //    *look = '\0';
  //    op = w65_op_from_param(param);
  //    op.md |= INDIRECT_LONG;
  //    ++look;
  //    while(*look&&ISSPACE(*look)) look++;
  //    if(*look==','){
  //      look++;
  //      while(*look&&ISSPACE(*look))look++;
  //      if(*look=='%')
  //       look++;
  //      if(*look=='Y'||*look=='y')
  //       op.md |= INDIRECT_Y;
  //       else
  //         as_bad(_("Invalid Index: %s"),look);
  //    }
  //  }else if(*param=='('){
  //    param++;
  //    char *look = param;
  //    while(*look&&*look!=')')
  //     look++;
  //    if(!*look)
  //       as_bad(_("Invalid operand: %s"),--param);
  //    *look = '\0';
  //    op = w65_op_from_param(param);
  //    if(op.md&INDEXED_X)
  //     op.md = (op.md&~INDEXED_X)|INDIRECT_X;
  //    else if(op.md&INDEXED_Y)
  //     op.md = (op.md&~INDEXED_Y)|INDIRECT_Y;
  //    else 
  //     op.md |= INDIRECT;

  //    ++look;
  //    while(*look&&ISSPACE(*look)) look++;
  //    if(*look==','){
  //      look++;
  //      while(*look&&ISSPACE(*look))look++;
  //      if(*look=='%')
  //       look++;
  //      if(*look=='X'||*look=='x')
  //       op.md |= INDEXED_X;
  //      else if(*look=='Y'||*look=='y')
  //       op.md |= INDEXED_Y;
  //       else
  //         as_bad(_("Invalid Index: %s"),look);
  //    }
  //  }else if(*param=='#'){
  //     ++param;
  //     op.md = IMM16; // This will be fixed when searching for opcodes. 
  //     if(ISDIGIT(*param)||*param=='-')
  //       op.value = strtol(param,NULL,0);
  //     else if(*param=='$')
  //       op.value = strtol(++param,NULL,16);
  //     else{
  //       char* look = param;
  //       while(*look&&ISSPACE(*look))look++;
  //       while(*look&&(ISALNUM(*look)||*look=='$'||*look=='.'||*look=='_'))
  //         look++;
  //       if(*look=='+'){
  //         *look = '\0';
  //         look++;
  //         if(ISDIGIT(*look)||*look=='-')
  //           op.value = strtol(look,&look,0);
  //       }else if(*look=='-'){
  //           char* pos = look;
  //           if(ISDIGIT(*(look+1)))
  //             op.value = strtol(look,&look,0);
  //           *pos = '\0';
  //       }
  //       *look = '\0';
  //       op.symbol = param;
  //     }
  //     if(op.value<0x100&&!op.symbol)
  //       op.md = IMM8;
  //   }else if(*param=='^'){
  //     ++param;
  //     op.md = IMM8;
  //     op.bank = true;
  //     op.symbol = param;
  //   }else{ // TODO: Direct Page Addressing
  //     char* tail;
  //     _Bool idx = 0;
  //     op.md = ABS;
  //     if(ISDIGIT(*param)||*param=='-')
  //       op.value = strtol(param,&tail,0);
  //     else if(*param=='$')
  //       op.value = strtol(++param,NULL,16);
  //     else{
  //       tail = param;
  //       while(*tail&&(ISALNUM(*tail)||*tail=='$'||*tail=='.'||*tail=='_'))
  //         tail++;
  //       if(*tail=='+'){
  //         *tail = '\0';
  //         tail++;
  //         if(ISDIGIT(*tail)||*tail=='-')
  //           op.value = strtol(tail,&tail,0);
  //       }else if(*tail=='-'){
  //           char* pos = tail;
  //           if(ISDIGIT(*(tail+1)))
  //             op.value = strtol(tail,&tail,0);
  //           *pos = '\0';
  //       }
  //       if(ISSPACE(*tail)){
  //         char* tail2 = ++tail;
          
  //         while(*tail2&&ISSPACE(*tail2))tail2++;
  //         if(*tail2==',')
  //           idx=1;
  //       }
  //       else if(*tail==',')
  //         idx = 1;
  //       *tail = '\0';
  //       op.symbol = param;
  //     }
  //     if(idx||ISSPACE(*tail)||*tail==','){
  //       idx |= *tail==',';
  //       tail++;
  //       while(*tail&&ISSPACE(*tail))tail++;
  //       if(!idx||*tail==','){
  //         idx = 1;
  //         tail++;
  //       }
  //       while(*tail&&ISSPACE(*tail))tail++;
  //       while(idx){
  //         if(*tail=='%')
  //           tail++;
  //         if(*tail=='x'||*tail=='X')
  //           op.md |= INDEXED_X;
  //         else if(*tail=='y'||*tail=='Y')
  //           op.md |= INDEXED_Y;
  //         else if(*tail=='d'||*tail=='D'){
  //           op.md = DIRECT;
  //           tail++;
  //           while(*tail&&ISSPACE(*tail))tail++;
  //           if(*tail==','||*tail=='+'){
  //             tail++;
  //             while(*tail&&ISSPACE(*tail))tail++;
  //             continue;
  //           }
  //         }else if(*tail=='s'||*tail=='S')
  //           op.md = STACK;
  //         else
  //           as_bad(_("Invalid Index: `%s'"),tail);
  //         break;
  //       }
  //     }
  //   }
  
   return op;

}

static _Bool is_immediate(w65_addr_mode op1){
  return op1<=IMM16&&IMMA<=op1;
}

static _Bool compatible_with(w65_addr_mode op1, w65_addr_mode* op2){
  if(op1==*op2)
    return true;
  else if(is_immediate(op1)&&is_immediate(*op2)){
    *op2 = op1;
    return true;
  }else if(op1==REL16&&*op2==ABS){
    *op2 = op1;
    return true;
  }else if(op1==REL8&&*op2==ABS){
    *op2 = op1;
    return true;
  }else{
    return false;
  }
}

static bfd_reloc_code_real_type
w65_addr_mode_to_reloc_code(w65_addr_mode md){
  switch(md&0xff){
    case IMM16:
    case ABS:
    return BFD_RELOC_16;
    case LONG:
    return BFD_RELOC_24;
    case IMM8:
    case DIRECT:
    return BFD_RELOC_8;
    case IMMA:
    if(w65_flg&M||w65_flg&E)
      return BFD_RELOC_8;
    else
      return BFD_RELOC_16;
    case IMMX:
    if(w65_flg&X||w65_flg&E)
      return BFD_RELOC_8;
    else
      return BFD_RELOC_16;
    case REL8:
      return BFD_RELOC_8_PCREL;
    case REL16:
      return BFD_RELOC_16_PCREL;
    default:
      abort();
  }
}

static void
print_insn(const w65_insn* insn,struct w65_operand* op){
  char* frag;
  int insn_size = w65_length_by_addr_mode(insn->oprs,w65_flg);
  frag = frag_more(insn_size);
  frag[0] = insn->opc;
  frag++;

  int reloc;
  if(op->bank)
    reloc = BFD_RELOC_WDC65816_BANK;
  else
    reloc = w65_addr_mode_to_reloc_code(op->md);

  fix_new_exp(frag_now,frag-frag_now->fr_literal,insn_size-1,&op->expr,op->md==REL8||op->md==REL16,reloc);
  md_number_to_chars(frag,0,insn_size-1);
}

static void
w65_assemble(char *op,char *size,char *param)
{
  struct w65_operand opr = {.md = 0};
  const char* op_real = op;

  for(char* c = op;*c;c++)
      *c = _tolower(*c);
  opr = w65_op_from_param(param);


  // Optional addr-mode suffix
  if(strcmp(size,"long")==0)
    opr.md |= LONG;
  else if(strcmp(size,"direct")==0)
    opr.md |= DIRECT;
  else if(*size==0); // pass
  else{
    as_bad (_("Unknown size suffix: `%s'"), size);
    return;
  }
  const w65_insn* actual_insn = (const w65_insn*)str_hash_find(insn_htab,op_real);
  if(!actual_insn){
    as_bad(_("Unknown Instruction: `%s'"),op_real);
    return;
  }else{
    while(streq(actual_insn->mnemonic,op)&&!compatible_with(actual_insn->oprs,&opr.md))actual_insn++;

    if(!streq(actual_insn->mnemonic,op_real)){
      as_bad(_("Cannot assemble instruction, no such opcode, or invalid parameter"));
      return;
    }
    print_insn(actual_insn,&opr);
  }
}

void
md_convert_frag (bfd *abfd ATTRIBUTE_UNUSED, asection *sec ATTRIBUTE_UNUSED, fragS *fragP ATTRIBUTE_UNUSED){}

arelent *
tc_gen_reloc (asection *section ATTRIBUTE_UNUSED, fixS * fixP )
{
  arelent * reloc;

  /* If symbols are local and resolved, then no relocation needed.  */
  if ( ((fixP->fx_addsy)
	&& (S_GET_SEGMENT (fixP->fx_addsy) == absolute_section))
       || ((fixP->fx_subsy)
	   && (S_GET_SEGMENT (fixP->fx_subsy) == absolute_section)))
    return NULL;

  reloc = XNEW (arelent);
  reloc->sym_ptr_ptr  = XNEW (asymbol *);
  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fixP->fx_addsy);
  reloc->address = fixP->fx_frag->fr_address + fixP->fx_where;
  reloc->addend = fixP->fx_offset;
  reloc->howto = bfd_reloc_type_lookup(stdoutput,fixP->fx_r_type);
  return reloc;
}

void
md_apply_fix (fixS *fixP ATTRIBUTE_UNUSED, valueT *valP ATTRIBUTE_UNUSED, segT seg ATTRIBUTE_UNUSED){\
  char *p = fixP->fx_where + fixP->fx_frag->fr_literal;
  valueT value = *valP;

  
  if(fixP->fx_done)
    return;

  if (fixP->fx_addsy == NULL
      && fixP->fx_pcrel == 0)
    fixP->fx_done = 1;
  else if (fixP->fx_pcrel == 1
      && fixP->fx_addsy != NULL
      && S_GET_SEGMENT (fixP->fx_addsy) == seg)
    fixP->fx_done = 1;
  else
    fixP->fx_done = 0;
  if(fixP->fx_done)
    md_number_to_chars(p,value,fixP->fx_size);
}

int
md_estimate_size_before_relax (fragS *fragp ATTRIBUTE_UNUSED, asection *seg ATTRIBUTE_UNUSED){
  return 0; // TODO: 
}

extern const char * w65_no_op_insn[];

void
md_assemble (char *op)
{
  
  char *param;
  reset_vars(op);

  while(*op&&ISSPACE(*op))
    op++;

  for (param = op; *param != 0 && !ISSPACE (*param); param++)
    ; // strip opcode, except for addr-mode selector
  *param++ = '\0';

  for(const char*const* no_op_insn = w65_no_op_insn;*no_op_insn;no_op_insn++){
    if(streq(op,*no_op_insn)){
      const w65_insn* actual_insn = (const w65_insn*)str_hash_find(insn_htab,op);
      char* frag = frag_more(1);
      *frag = actual_insn->opc;
      return;
    }
  }

  char *size;
  for(size = op;*size != 0 && *size != '.';size++);

  if(*size)
    *size++ = '\0';

  w65_assemble(op,size,param);
}
