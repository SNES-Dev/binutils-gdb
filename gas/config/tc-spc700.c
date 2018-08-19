#include "as.h"
#include "safe-ctype.h"
#include "subsegs.h"
#include "opcode/spc700.h"
#include <assert.h>

const char comment_chars[] = ";\0";
const char line_comment_chars[] = "/;\0";
const char line_separator_chars[] = "\0";
const char EXP_CHARS[] = "eE\0";
const char FLT_CHARS[] = "RrFf\0";

const char * md_shortopts = ""; /* None yet.  */

#define INS_SPC700    1
#define INS_UNDOC  2
#define INS_UNPORT 4


struct option md_longopts[] =
{
  { NULL, no_argument, NULL, 0 }
} ;

#define MAX_TOK 5 //max number of tokens to match
#define TEXTTOKENLEN 256 //max length of symbols

typedef enum OperandTerminal {
  OpTerminal_End = 0, // '\0'
  OpTerminal_Symbol = 1,
  OpTerminal_Abs = 2, //!1234
  OpTerminal_Imm = 3, //#1234
  OpTerminal_Value = 4,  //255
  OpTerminal_Dp = 4,  //255
  OpTerminal_RegA = 5,
  OpTerminal_RegX = 6,
  OpTerminal_RegY = 7,
  OpTerminal_RegYA = 8,
  OpTerminal_RegSP = 9,
  OpTerminal_RegPSW = 10,
  OpTerminal_RegIndirectOpen = 11, // (
  OpTerminal_RegIndirectClose = 12 , // )
  OpTerminal_DPIndirectOpen = 13, // [
  OpTerminal_DPIndirectClose = 14, // ]
  OpTerminal_Plus = 15,
  OpTerminal_Unreckognized = 256,
  OpTerminal_None = 256
} OperandTerminal;

typedef struct OperandInfo {
  OperandTerminal terminals[5];
  int immediate_or_addr;
  int numTerminals;
  //1 if the value is a symbol with name 'symbolname'
  //0 if the value is a constant with value 'immediate_or_addr'
  int value_is_symbol;
  spc700_argtype argtype;
  char symbolname[TEXTTOKENLEN + 1];
} OperandInfo;

static void emit_byte(OperandInfo* opinfo, bfd_reloc_code_real_type r_type);
static void emit_word(OperandInfo* opinfo);
static void assemble(spc700_opcode* insn, OperandInfo* opinfo);

size_t md_longopts_size = sizeof (md_longopts);

extern int coff_flags;


static void s_dpoffs(int arg ATTRIBUTE_UNUSED);

/* our dpmode state. 0 means DP is an offset from 0x0000, 1 means it is an offset from 0x00FF */
int g_dpmode = 0;

/* Declaration of the ".dpoffs" directive. Assembler hint for what the direct page offset currently is.
   This affects fixups and linker relaxation for direct page addressing modes. The direct page can either point to
   address 0x0000 or 0x0100 depending on a CPU flag. For correct assembly generation, the assembler must at all times know
   what the current mode is. */
const pseudo_typeS md_pseudo_table[] = {
  {"dpoffs", s_dpoffs, 0},
  {0, 0, 0}
};

/* Detect psuedo directive ".dpoffs low|high"
   Gives the assembler a hint of what address the Direct Page offset is relative to.
   ".dpoffs low" means that DP relative address modes like "mov A,40" is relative to address !0x0000
   ".dpoffs high" means that DP relative address modes like "mov A,40" is relative to address !0x0100
   Direct Page relative addresses are addresses without a '!' prefix (or any other prefix). They are encoded as a single unsigned byte.

   Why is this .dpoffs psuedo directive required? Because the assembler can't track the state of the DP offset flag alone at compile time.
   Nonetheless the assembler needs to know this information in order to calculate proper offsets from labels.
   */
static void s_dpoffs(int arg ATTRIBUTE_UNUSED){
  (void)arg;
  while (*input_line_pointer == ' ') input_line_pointer++;
  if(!strncmp(input_line_pointer, "low", 3)){
    input_line_pointer += 3;
    g_dpmode = 0; //DP offsets are relative to address !0x0000
  } else if(!strncmp(input_line_pointer, "high", 4)){
    input_line_pointer += 4;
    g_dpmode = 1; //DP offsets are relative to address !0x0100
  }
}


/* parsing of architecture-specific options. Currently we have none */
int md_parse_option (int c ATTRIBUTE_UNUSED, const char* arg ATTRIBUTE_UNUSED){
  return 1;
}

/* display usage of architecture-specific options. Currently we have none */
void md_show_usage (FILE * f ATTRIBUTE_UNUSED){

}

/* initialize symbols/expressionS'es for our registers here so that registers can be detected by expr()*/
void md_begin (void){

  /* no linker relaxing yet */
  linkrelax = 0;
}

/* cleanup after md_begin if required */
void spc700_md_end (void){

}

/* Hook into every line from the assembly file. We can use this to override directives such as .long and .byte
   Not sure if we actually need this override. The defaults should do the right thing.  */
#if 0
int spc700_start_line_hook (void){
  return 0;
}
#endif

/* Return a symbolS which is the undefined symbol. We can just return NULL here */
symbolS * md_undefined_symbol (char *name ATTRIBUTE_UNUSED){
  return NULL;
}

/* hook into atof used by expr(). Supporting floats on the spc700 would be ridiculous, so report an error if this happens. */
const char* md_atof (int type ATTRIBUTE_UNUSED, char *litP ATTRIBUTE_UNUSED, int *sizeP ATTRIBUTE_UNUSED){
  return _("floating point numbers are not implemented");
}

/* Align sections to whatever the input is. That is, we support 1-byte section alignments- */
valueT md_section_align (segT seg ATTRIBUTE_UNUSED, valueT size){
  return size;
}

/* This function is called to get the address/offset of whatever PC is when fixing up pc-relative relocs.
    Some architectures like ARM evaluates PC to the address of the current instruction + 8 bytes.
    On the SPC700, pc-relative addresses are directly relative to the address of the executed instruction.
    We subtract 1 from fr_address because it points to one past the opcode byte */

long md_pcrel_from (fixS * fixp){
  return fixp->fx_where + fixp->fx_frag->fr_address; //0 or +1 ? Assume that fr_address points to the first operand, so PC will be one byte back
}









/* This is our entrypoint, so to speak.
   This is how gas' API works:

   'str' points directly to the start of an instruction mnemonic.
   After we have parsed the mnemonic, we forward advance 'str' and parse the operand expressions.
   Some assembly dialects have prefixes for operand sizes. After we have figured out the operand size,
   we set the global variable 'input_line_pointer' to point to the start of an operand expression and then
   call the macro called 'expression'.
   The macro writes gives us an 'expressionS' instance. This can be a simple constant or a more complex expression;
   possibly consisting of multiple symbol references and constants. For example "mov acc, label1+0x40*othersymbol"

   When we get our operand expressionS for all our operands that our instruction have defined, we check if our expressions needs to be resolved.
   If we are lucky and find the symbols in the symbol table right away, we just plug in the value of the symbol. If our expression is already a constant,
   then just use that constant. However, if our expression depends on symbols not yet defined in the symbol table, we have to emit a fixup.
   If possible, the fixups are resolved at the end of the file; possibly by doing second pass. If a symbol for a fixup is truly external, we output a relocation which will be handled by the linker later.

   So now we have our operands resolved (or not) and we want to emit the instruction bytes. We do that by calling frag_more() to get allocated space for our current fragment.
   An output section is split into many so-called fragments which form a linked list. This is to be able to support relaxation.
*/

/*
typedef enum spc700_argtype {
  SPC700_Argtype_None = 0,
  SPC700_Argtype_A,                        //A
  SPC700_Argtype_X,                        //X
  SPC700_Argtype_Y,                        //Y
  SPC700_Argtype_SP,                       //SP
  SPC700_Argtype_YA,                       //YA
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
  SPC700_Argtype_DP_Indirect_Plus_Y        //((dp)+Y) (dp is an absolute double-pointer, where the looked up pointer gets added to Y)
} spc700_argtype;
*/



/*
//todo: use this to override expr()
void md_operand(expressionS * exp){
  char c = *input_line_pointer;

  switch (c)
    {

    }
}
*/

/*
    A
    X
    Y
    YA
    SP (only mov)
    PSW (only push/pop)
    #imm
    (X)
    (X)+
    dp
    dp+X
    dp+Y
    [dp+X]
    [dp]+Y
    !abs
    !abs+X
    !abs+Y
    [!abs+X] <---- JMP
    PCALL upage
    TCALL n
*/











/* The index of this table matches the index of spc700_argtype in opcode/spc700.h */
OperandTerminal op2argtype_table[23][7] = {
  {OpTerminal_None,             OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //Dummy
  {OpTerminal_RegA,             OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //A
  {OpTerminal_RegX,             OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //X
  {OpTerminal_RegY,             OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //Y
  {OpTerminal_RegYA,            OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //YA
  {OpTerminal_RegSP,            OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //SP
  {OpTerminal_RegPSW,           OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //PSW
  {OpTerminal_Imm,              OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //#imm
  {OpTerminal_Value,            OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //dp
  {OpTerminal_Abs,              OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //!abs
  {OpTerminal_None,             OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //PCRel, (special case)
  {OpTerminal_None,             OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //PCALL page (special case)
  {OpTerminal_None,             OpTerminal_None,  OpTerminal_None,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //TCALL imm (special case)
  {OpTerminal_RegIndirectOpen,  OpTerminal_RegX,  OpTerminal_RegIndirectClose,  OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //(X)
  {OpTerminal_RegIndirectOpen,  OpTerminal_RegY,  OpTerminal_RegIndirectClose,  OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //(Y)
  {OpTerminal_RegIndirectOpen,  OpTerminal_RegX,  OpTerminal_RegIndirectClose,  OpTerminal_Plus,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //(X)+
  {OpTerminal_Value,            OpTerminal_Plus,  OpTerminal_RegX,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //dp+X
  {OpTerminal_Value,            OpTerminal_Plus,  OpTerminal_RegY,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //dp+Y
  {OpTerminal_Abs,              OpTerminal_Plus,  OpTerminal_RegX,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //abs+X
  {OpTerminal_Abs,              OpTerminal_Plus,  OpTerminal_RegY,              OpTerminal_None,            OpTerminal_None,            OpTerminal_None,  OpTerminal_None},         //abs+Y
  {OpTerminal_DPIndirectOpen,   OpTerminal_Value, OpTerminal_Plus,              OpTerminal_RegX,            OpTerminal_DPIndirectClose, OpTerminal_None,  OpTerminal_None},         //[dp+X]
  {OpTerminal_DPIndirectOpen,   OpTerminal_Value, OpTerminal_DPIndirectClose,   OpTerminal_Plus,            OpTerminal_RegY,            OpTerminal_None,  OpTerminal_None},         //[dp]+Y
  {OpTerminal_DPIndirectOpen,   OpTerminal_Abs,   OpTerminal_Plus,              OpTerminal_RegX,            OpTerminal_DPIndirectClose, OpTerminal_None,  OpTerminal_None}          //JMP [!abs+X]
};

#define CASESTR(x) case x: return #x


static const char* Terminal2Str(OperandTerminal terminal){
    switch(terminal){
        CASESTR(OpTerminal_End);
        CASESTR(OpTerminal_Symbol);
        CASESTR(OpTerminal_Abs);
        CASESTR(OpTerminal_Imm);
        CASESTR(OpTerminal_Dp);
        CASESTR(OpTerminal_RegA);
        CASESTR(OpTerminal_RegX);
        CASESTR(OpTerminal_RegY);
        CASESTR(OpTerminal_RegYA);
        CASESTR(OpTerminal_RegSP);
        CASESTR(OpTerminal_RegPSW);
        CASESTR(OpTerminal_RegIndirectOpen);
        CASESTR(OpTerminal_RegIndirectClose);
        CASESTR(OpTerminal_DPIndirectOpen);
        CASESTR(OpTerminal_DPIndirectClose);
        CASESTR(OpTerminal_Plus);
        CASESTR(OpTerminal_None);
    }
}

static const char* ArgType2Str(spc700_argtype argtype){
    switch(argtype){
        CASESTR(SPC700_Argtype_None);
        CASESTR(SPC700_Argtype_A);
        CASESTR(SPC700_Argtype_X);
        CASESTR(SPC700_Argtype_Y);
        CASESTR(SPC700_Argtype_YA);
        CASESTR(SPC700_Argtype_SP);
        CASESTR(SPC700_Argtype_PSW);
        CASESTR(SPC700_Argtype_Immediate);
        CASESTR(SPC700_Argtype_DP);
        CASESTR(SPC700_Argtype_AbsAddr);
        CASESTR(SPC700_Argtype_PcRelAddr);
        CASESTR(SPC700_Argtype_PCallAddr);
        CASESTR(SPC700_Argtype_TCallAddr);
        CASESTR(SPC700_Argtype_X_Indirect);
        CASESTR(SPC700_Argtype_Y_Indirect);
        CASESTR(SPC700_Argtype_X_Indirect_AutoIncr);
        CASESTR(SPC700_Argtype_DP_Plus_X);
        CASESTR(SPC700_Argtype_DP_Plus_Y);
        CASESTR(SPC700_Argtype_AbsAddr_Plus_X);
        CASESTR(SPC700_Argtype_AbsAddr_Plus_Y);
        CASESTR(SPC700_Argtype_DP_Plus_X_Indirect);
        CASESTR(SPC700_Argtype_DP_Indirect_Plus_Y);
        CASESTR(SPC700_Argtype_JMP_ABS_Plus_X_Indirect);
    }
}

static void skipspace(char** line){
    while(ISSPACE(**line)){
        (*line)++;
    }
}



//save immediates and addresses from our tokenizer here
int immediate_dp_abs;

//save symbols from our tokenizer here
char textToken[TEXTTOKENLEN+1];

//tokenizer for our parser
static OperandTerminal get_spc700_token(char* stream, int* consumed, int* value_is_symbol){
  *consumed = 0;
  *value_is_symbol = 0;

  char* p = 0;
  memset(textToken, 0, TEXTTOKENLEN+1);

  if(*stream == '\0'){
        // ====================== handle end of line ======================
        *consumed = 0;
        return OpTerminal_End;
  } else if(*stream == '#'){
        //====================== handle immediates ======================
        stream++;
        int c = 0;
        //call recursively because we expect a "DP" number after a '#'
        OperandTerminal term = get_spc700_token(stream, &c, value_is_symbol);
        if(term != OpTerminal_Value){
          //as_bad (_("expected number after '#'"));
          //ignore_rest_of_line ();
          return OpTerminal_Unreckognized;
        }
        *consumed = c+1;
        return OpTerminal_Imm;
  } else if(*stream == '!'){
        //====================== handle absolute addresses ======================
        stream++;
        int c = 0;
        //call recursively because we expect a "DP" number after a '#'
        OperandTerminal term = get_spc700_token(stream, &c, value_is_symbol);
        if(term != OpTerminal_Value){
          //as_bad (_("expected number after '#'"));
          //ignore_rest_of_line ();
          return OpTerminal_Unreckognized;
        }
        *consumed = c+1;
        return OpTerminal_Abs;
  } else if(*stream == '('){
        //====================== handle reg indirect ======================
        *consumed = 1;
        return OpTerminal_RegIndirectOpen;
  } else if(*stream == ')'){
        //====================== handle reg indirect ======================
        *consumed = 1;
        return OpTerminal_RegIndirectClose;
  } else if(*stream == '['){
        //====================== handle dp indirect ======================
        *consumed = 1;
        return OpTerminal_DPIndirectOpen;
  } else if(*stream == ']'){
        //====================== handle dp indirect ======================
        *consumed = 1;
        return OpTerminal_DPIndirectClose;
  } else if(*stream == '+'){
        //================= handle add/plus in dp indirect ===============
        *consumed = 1;
        return OpTerminal_Plus;
  } else if(ISDIGIT(*stream)){
        //====================== handle DP offsets ======================
        p = textToken;
        while(ISDIGIT(*stream) && (*consumed < TEXTTOKENLEN)){
          *p++ = *stream++;
          (*consumed)++;
        }
        if(ISDIGIT(*stream)){
          //as_bad (_("number too big."));
          //ignore_rest_of_line ();
          *consumed = 0;
          return OpTerminal_Unreckognized;
        }
        //save DP operand in immediate_dp_abs global so the parser can read it later
        sscanf(textToken, "%d", &immediate_dp_abs);
        return OpTerminal_Value;
  } else if(ISALPHA(*stream)){
        //====================== handle labels and registers ======================
        p = textToken;
        while(ISALNUM(*stream) && (*consumed < TEXTTOKENLEN)){
          *p++ = *stream++;
          (*consumed)++;
        }
        if(ISALNUM(*stream)){
          //as_bad (_("symbol length exceeded."));
          //ignore_rest_of_line ();
          return OpTerminal_Unreckognized;
        }
        if(!strcmp(textToken, "A")){
          return OpTerminal_RegA;
        } else if(!strcmp(textToken, "X")){
          return OpTerminal_RegX;
        } else if(!strcmp(textToken, "Y")){
          return OpTerminal_RegY;
        } else if(!strcmp(textToken, "YA")){
          return OpTerminal_RegYA;
        } else if(!strcmp(textToken, "SP")){
          return OpTerminal_RegSP;
        } else if(!strcmp(textToken, "PSW")){
          return OpTerminal_RegPSW;
        } else {
          *value_is_symbol = 1;
          return OpTerminal_Value;
        }
  } else {
        //====================== Unknown token ======================
        return OpTerminal_Unreckognized;
  }
}


static int parse_operand(char* line, OperandInfo* opinfo, int* fin){
  int consumed = 0;
  int i = 0;
  int value_is_symbol = 0;

  memset(opinfo, 0, sizeof(OperandInfo));
  //opinfo->value_is_symbol = 0;
  //opinfo->numTerminals = 0;

  *fin = 0;
  for(; i < MAX_TOK; i++){
    int c = 0;
    OperandTerminal term = get_spc700_token(line, &c, &value_is_symbol);
    if(term == OpTerminal_Unreckognized){
        return -1;
    } else if(term == OpTerminal_End){
      *fin = 1;
      consumed += c;
      return consumed;
    }
    consumed += c;
    line += c;
    opinfo->terminals[opinfo->numTerminals++] = term;


    /* OpTerminal_Dp == OpTerminal_Value */
    if(term == OpTerminal_Abs || term == OpTerminal_Dp || term == OpTerminal_Imm){
        //fetch the value or symbol (global state) from our lexer
        if(value_is_symbol){
            strcpy(opinfo->symbolname, textToken);
            opinfo->value_is_symbol = 1;
        } else {
            opinfo->immediate_or_addr = immediate_dp_abs;
            opinfo->value_is_symbol = 0;
        }
    }
    if(*line == ',' || *line == '\0'){
      return consumed;
    }
  }
  return -1;
}



static int get_operand(char* line, OperandInfo* opinfo, int* finished){
  int c;
  int i = 0, j;

  c = parse_operand(line, opinfo, finished);
  if(c < 0){
    return -1;
  }
  if(*finished){
      return 0;
  }

  for(; i < 23; i++){
    int match = 1;
    for(j = 0; j < opinfo->numTerminals; j++){
      if(op2argtype_table[i][j] != opinfo->terminals[j]){
        match = 0;
        break;
      }
    }
    if(match){
      opinfo->argtype = (spc700_argtype)i;
      return c;
    }
  }
  return -1;
}

static spc700_opcode* get_insn(char* mnemonic, spc700_argtype argtypes[3]){
    int i;
    for(i = 0; i < (int)spc700_opcode_table_len; i++){
        spc700_opcode* op = &spc700_opcodes[i];
        if(!strcmp(op->name, mnemonic) && (op->argtypes[0] == argtypes[0]) && (op->argtypes[1] == argtypes[1]) && (op->argtypes[2] == argtypes[2])){
            return op;
        }
    }
    return NULL;
}

void md_assemble (char* str){
    spc700_opcode* insn;
    OperandInfo opinfo[3] = {0};
    spc700_argtype argtypes[3] = {SPC700_Argtype_None, SPC700_Argtype_None, SPC700_Argtype_None};
    char mnemonic[8] = {0};
    int c,i,f,n;
    char* p;



    p = mnemonic;
    if(!ISALPHA(*str)){
        as_bad (_("mnemonic '%s' must start with an alpha character"), mnemonic);
        return;
    }

    while(*str && ISALNUM(*str)){
        *p++ = TOUPPER(*str++);
    }
    skipspace(&str);

    n = 0;
    while(1) {
        if ((c = get_operand(str, &opinfo[n], &f)) < 0) {
            as_bad (_("Error while parsing operand"));
            break;
        }
        n++;
        str += c;
        if(f || !*str){
            break;
        }
        if(!(*str == ',')){
            as_bad (_("expected comma separator"));
            break;
        }
        str++;
    }

    for(i = 0; i < n; i++) {
        argtypes[i] = opinfo[i].argtype;
    }
    insn = get_insn(mnemonic, argtypes);
    if(!insn){
        as_bad (_("unknown instruction '%s'"), mnemonic);
        return;
    }

    //printf("mnemonic is %s\n", mnemonic);
    //printf("opcode is %02X\n", (unsigned int)insn->opcode);
    //printf("instruction size: %u\n", insn->size);
    //printf("Successfully parsed %d operands\n", n);
    //for(i = 0; i < n; i++){
    //    printf("operand %d: argtype %s\n", (i+1), ArgType2Str(opinfo[i].argtype));
    //}

    assemble(insn, opinfo);
}



static void assemble(spc700_opcode* insn, OperandInfo* opinfo){


  /*
  Explanation below regarding frag_more(), fix_new_exp() and frags.

  p = frag_more(num_bytes)
  if (val->X_op != O_constant){
    fix_new_exp (frag_now, p - frag_now->fr_literal, 2, val, FALSE, BFD_RELOC_16);
   }

   arguments:
   fix_new_exp(fragment, offset, size, expr, pcrel?, reloc_real_type)

   frag_now is a pointer to the current frag, and frag_now->fr_literal is the base pointer to the allocated storage for the frag.
   when you call frag_more, the current position inside frag_now->fr_literal is advanced with the size you asked for.
   So the expression "p - frag_now->fr_literal" becomes the offset of p relative to frag_now->fr_literal, which is the offset fix_new_exp expects.
   In other words, p is greater or equal to frag_now->fr_literal. When subtracting the two pointers, you should use ptrdiff_t.
  */


  /*
  TODO:

  Major stuff (in order of work and difficulty):
  * This function. Every value and address type (dp, abs, pcrel, imm) when refered to by a symbol needs to be marked for fixup.
    This is done by calling fix_new_exp and passing on the reloc_real_type type associated with the relocation.
    Some fixups are context-dependent; in particular DP (direct page) offsets, because the base address of the direct page can be changed
    by the CLRP/SETP instructions. The assembler gets the correct DP offset by a hint via an GAS assembly directive called ".dpoffs",
    which takes the arguments "high" or "low". See the top of this file for more info. Unfortunately in the DP case, this means we get
    double the amount of reloc types! Yikes :-(   One for DP-HIGH and one for DP-LOW.
  * Implement md_apply_fix() in this file, which does local fixups.
  * Implement tc_gen_reloc() in this file, which creates/emits external relocs (local fixups that fail)
  * Add the remaining instructions to the instruction table.

  * Add the missing reloc types. Needs to be done in libopcode and libbfd. Both the reloc_real_type types and the internal reloc types.
    Of the special reloc types we need, what I can remember from the top of my head is two different reloc types for DP (high/low baseaddr),
    as well as reloc types for 4-bit immediates used by PCALL/TCALL, and some other instructions that store data inside the opcode itself.
    We also need reloc types for CALL, BRA, Bxx and JMP. Some of these are PC-relative and signedness can differ. That is, some displacements
    are allowed to be negative. (COMMON RELOCS FIXED, READY FOR TESTING)

  * Finish the reloc fixup code and reloc type conversion code in libbfd used by the linker. (FIXUP CODE DONE, READY FOR TESTING)
  * Add the missing argument types to spc700_argtype.
  * Add patterns matching the new argtypes to op2argtype_table.
  * Trivially add the missing argument types tp ArgType2Str() if we want to easily print the enum

  */
  char* out;
  int i;
/* insn->size */
  out = frag_more(1);

  *out++ = (insn->opcode&0xFF);

  for(i = 0; i < (int)insn->numargs; i++){
    int addrmode = opinfo[i].argtype;
    switch(addrmode){
      /* Implied arguments, so do nothing. Fallthrough to a break*/
      case SPC700_Argtype_A:
      case SPC700_Argtype_X:
      case SPC700_Argtype_Y:
      case SPC700_Argtype_YA:
      case SPC700_Argtype_SP:
      case SPC700_Argtype_PSW:
      case SPC700_Argtype_X_Indirect:
      case SPC700_Argtype_Y_Indirect:
      case SPC700_Argtype_X_Indirect_AutoIncr:
        break;

      /* rel, immediates and direct page offsets are 8-bits */
      case SPC700_Argtype_PcRelAddr:
      emit_byte(&opinfo[i], BFD_RELOC_SPC700_PC8);
      break;
      case SPC700_Argtype_Immediate:
      emit_byte(&opinfo[i], BFD_RELOC_SPC700_IMM8);
      break;
      case SPC700_Argtype_DP:
      case SPC700_Argtype_DP_Plus_X:
      case SPC700_Argtype_DP_Plus_Y:
      case SPC700_Argtype_DP_Plus_X_Indirect:
      case SPC700_Argtype_DP_Indirect_Plus_Y:
        /* Thanks to our custom .dpmode directive,
        we can emit the correct relocation depending on the current direct page base */
        if(g_dpmode == 0){
          emit_byte(&opinfo[i], BFD_RELOC_SPC700_DPLO8);
        } else if(g_dpmode == 1){
          emit_byte(&opinfo[i], BFD_RELOC_SPC700_DPHI8);
        }
        break;

      /* SPC700 is little endian, so LSB first.
         TODO: Use one of GAS' protable conversion functions */
      case SPC700_Argtype_AbsAddr:
      case SPC700_Argtype_AbsAddr_Plus_X:
      case SPC700_Argtype_AbsAddr_Plus_Y:
      case SPC700_Argtype_JMP_ABS_Plus_X_Indirect:
        emit_word(&opinfo[i]);
        break;

      case SPC700_Argtype_PCallAddr:
      case SPC700_Argtype_TCallAddr:
      as_bad (_("pcall/tcall not yet supported"));
      break;

      default:
      as_bad (_("illegal address mode in assemble()!"));
      break;
    }
  }
}


static void emit_byte(OperandInfo* opinfo, bfd_reloc_code_real_type r_type)
{
  expressionS val = {0};
  symbolS* s = NULL;
  char *p;

  //we should never call emit_byte with a 16-bit reloc
  assert(r_type != BFD_RELOC_SPC700_ABS16);

  p = frag_more (1);
  *p = 0;

  if (!opinfo->value_is_symbol){
      *p = opinfo->immediate_or_addr&0xFF;
  } else {
      s = symbol_find_or_make(opinfo->symbolname);
      //symbol_set_value_expression(val, &ex);
      val.X_op = O_symbol;
      val.X_add_symbol = s;
      /* TODO: Add support for addends :) */
      val.X_add_number = 0;
      fix_new_exp (frag_now, p - frag_now->fr_literal, 1, &val, (r_type == BFD_RELOC_SPC700_PC8) ? TRUE : FALSE, r_type);
  }
}

static void emit_word(OperandInfo* opinfo)
{
  expressionS val = {0};
  symbolS* s = NULL;
  char *p;

  p = frag_more (2);
  p[0] = 0;
  p[1] = 0;

  if (!opinfo->value_is_symbol){
      p[0] = opinfo->immediate_or_addr&0xFF;
      p[1] = (opinfo->immediate_or_addr>>8)&0xFF;
  } else {
      s = symbol_find_or_make(opinfo->symbolname);
      //symbol_set_value_expression(val, &ex);
      val.X_op = O_symbol;
      val.X_add_symbol = s;
      /* TODO: Add support for addends :) */
      val.X_add_number = 0;
      fix_new_exp (frag_now, p - frag_now->fr_literal, 2, &val, FALSE, BFD_RELOC_SPC700_ABS16);
  }
}




/*Note: If we define RELOC_EXPANSION_POSSIBLE in tc_spc700.h, then we can
  Process multiple fixups at once for a section here.
  Just traverse the linked list in fixP->fx_next until it's NULL
*/
void md_apply_fix (fixS * fixP, valueT* valP, segT seg ATTRIBUTE_UNUSED){
  long val = * (long *) valP;
  char *p_lit = fixP->fx_where + fixP->fx_frag->fr_literal;

  fixP->fx_no_overflow = 1;
  fixP->fx_done = 0;
  fixP->fx_pcrel = 0;

  if(fixP->fx_r_type == BFD_RELOC_SPC700_PC8){
    fixP->fx_pcrel = 1;
  }
  /* always create relocs if we have symbols */
  if(fixP->fx_addsy){
    return;
  }

  fixP->fx_done = 1;

  switch (fixP->fx_r_type){
    case BFD_RELOC_SPC700_ABS16:
      *p_lit++ = val&0xFF;
      *p_lit++ = (val>>8)&0xFF;
      break;
    case BFD_RELOC_SPC700_DPLO8:
      *p_lit++ = val&0xFF;
      break;
    case BFD_RELOC_SPC700_DPHI8:
      *p_lit++ = val&0xFF;
      break;
    case BFD_RELOC_SPC700_IMM8:
      if (val > 255 || val < -128){
        as_warn_where (fixP->fx_file, fixP->fx_line, _("overflow"));
      }
      *p_lit++ = val;
      break;
    case BFD_RELOC_SPC700_PC8:
      fixP->fx_no_overflow = (-128 <= val && val < 128);
      if (!fixP->fx_no_overflow){
          as_bad_where (fixP->fx_file, fixP->fx_line, _("relative jump out of range"));
      }
      *p_lit++ = val;
      break;
    case BFD_RELOC_SPC700_PCALL8:
      printf (_("md_apply_fix: BFD_RELOC_SPC700_PCALL8 not supported yet\n"));
      abort();
      break;
    default:
      printf (_("md_apply_fix: unknown r_type 0x%x\n"), fixP->fx_r_type);
      abort ();
  }
  printf(_("md_apply_fix: %s:%d : fixup of r_type 0x%x, constant with value %lu\n"), fixP->fx_file, fixP->fx_line, fixP->fx_r_type, val);
}

/* find workaround, this function is buggy in the z80 port */
arelent* tc_gen_reloc (asection *seg ATTRIBUTE_UNUSED , fixS *fixp){
  arelent *reloc;

  if (! bfd_reloc_type_lookup (stdoutput, fixp->fx_r_type))
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
        _("reloc %d not supported by object file format"),
        (int) fixp->fx_r_type);
      return NULL;
    }

  reloc               = XNEW (arelent);
  reloc->sym_ptr_ptr  = XNEW (asymbol *);
  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fixp->fx_addsy);
  reloc->address      = fixp->fx_frag->fr_address + fixp->fx_where;
  reloc->howto        = bfd_reloc_type_lookup (stdoutput, fixp->fx_r_type);
  reloc->addend       = fixp->fx_offset;

  return reloc;
}


/*
tc-w65 used:

void md_begin(void);
void w65_expression(expressionS* dest);
void md_assemble(char* str);
symbolS * md_undefined_symbol(char* name);
char* md_atof (char type, char* litP, int* sizeP);
int md_parse_option (int c, char* a);
void md_convert_frag (object_headers* headers, segT seg, fragS* fragP);           -- Called after relaxing, change the frags so they know how big they are.
valueT md_section_align(segT seg, valueT size);
void md_apply_fix3(fixS* fixP, valueT* valP, segT seg)
void md_number_to_chars(char *ptr, valueT use, int nbytes)
long md_pcrel_from (fixS* fixP)
void tc_coff_symbol_emit_hook (symbolS* x)
short tc_coff_fix2rtype (fixS* fix_ptr)
void tc_reloc_mangle(fixS *fix_ptr, struct internal_reloc *intr, bfd_vma base)
int tc_coff_sizemachdep(fragS* frag)
int md_estimate_size_before_relax (fragS *fragP, segT segment_type)       //compute resizes / gaps before linker relaxation
void md_show_usage(FILE* stream)
*/
