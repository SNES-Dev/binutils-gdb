#include "config.h"

#include <limits.h>



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

/* Generic assembler global variables which must be defined by all targets.  */

/* Characters which always start a comment.  */
const char comment_chars[] = "#";

/* Characters which start a comment at the beginning of a line.  */
const char line_comment_chars[] = "#";

/* This array holds machine specific line separator characters.  */
const char line_separator_chars[] = ";";

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
  return 0;
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
md_pcrel_from (fixS *fixp)
{
  return fixp->fx_frag->fr_address + fixp->fx_where;
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
  bfd_vma value;
  const char* symbol;
};

static struct w65_operand
w65_op_from_param(char *param){
   struct w65_operand op = {.md = 0};
   while(ISSPACE(*param))param++;
   if(!*param)
    op.md = IMPLIED;
   else if(*param=='['){
     param++;
     char *look = param;
     while(*look&&*look!=']')
      look++;
     if(!*look)
        as_bad(_("Invalid operand: %s"),--param);
     *look = '\0';
     op = w65_op_from_param(param);
     op.md |= INDIRECT_LONG;
   }else if(*param=='('){
     param++;
     char *look = param;
     while(*look&&*look!=')')
      look++;
     if(!*look)
        as_bad(_("Invalid operand: %s"),--param);
     *look = '\0';
     op = w65_op_from_param(param);
     
     ++look;
     while(*look&&ISSPACE(*look)) look++;
     if(*look==','){
       if(*++look=='X')
        op.md |= INDIRECT_X;
       else if(*look=='Y')
        op.md |= INDIRECT_Y;
        else
          as_bad(_("Invalid Index: %s"),look);
     }else{
       op.md |= INDIRECT;
     }
   }else if(*param=='#'){
      ++param;
      op.md = IMM16; // This will be fixed when searching for opcodes. 
      if(ISDIGIT(*param)||*param=='-')
        op.value = atoi(param);
      else if(*param=='$')
        op.value = strtol(++param,NULL,16);
      else{
        char* look = param;
        while(*look&&(ISALNUM(*look)||*look=='$'||*look=='.'||*look=='_'))
          look++;
        *look = '\0';
        op.symbol = param;
      }
      if(op.value<0x100&&!op.symbol)
        op.md = IMM8;
    }else{ // TODO: Direct Page Addressing
      char* tail;
      _Bool idx = 0;
      op.md = ABS;
      if(ISDIGIT(*param)||*param=='-')
        op.value = strtol(param,&tail,10);
      else if(*param=='$')
        op.value = strtol(++param,NULL,16);
      else{
        tail = param;
        while(*tail&&(ISALNUM(*tail)||*tail=='$'||*tail=='.'||*tail=='_'))
          tail++;
        if(*tail==',')
          idx = 1;
        *tail = '\0';
        op.symbol = param;
      }
      (void)idx;
    }
  
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
print_insn(const w65_insn* insn,const struct w65_operand* op){
  char* frag;
  int insn_size = w65_length_by_addr_mode(insn->oprs,w65_flg);
  frag = frag_more(insn_size);
  frag[0] = insn->opc;
  frag++;

  

  if(op->symbol!=0){
    bfd_reloc_code_real_type reloc_ty = w65_addr_mode_to_reloc_code(op->md);
    reloc_howto_type* howto = bfd_reloc_type_lookup(stdoutput,reloc_ty);
    md_number_to_chars(frag,0,insn_size-1);
    symbolS* sym = symbol_find_or_make(op->symbol);
    fix_new(frag_now,frag - frag_now->fr_literal,insn_size-1,sym,0,howto->pc_relative,reloc_ty);
  }else{
    md_number_to_chars(frag,op->value,insn_size-1);
  }
}

static void
w65_assemble(char *op,char *size,char *param)
{
  struct w65_operand opr = {.md = 0};
  const char* op_real = op;

  // special case, lea ABS => lda immA, lea (addr)=>lda addr
  if(strcmp(op,"lea")==0){
    op_real = "lda";
    opr = w65_op_from_param(param);
  }else{
    for(char* c = op;*c;c++)
      *c = _tolower(*c);
    w65_op_from_param(param);
  }


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
  return reloc;
}

void
md_apply_fix (fixS *fixP ATTRIBUTE_UNUSED, valueT *valP ATTRIBUTE_UNUSED, segT seg ATTRIBUTE_UNUSED){}

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