#include "config.h"

#include <limits.h>



#include "as.h"
#include "safe-ctype.h"
#include "opcode/w65.h"

#ifdef OBJ_ELF
#include "elf/w65.h"
#include "dwarf2dbg.h"
#endif

#define WORD_SHIFT  16


/* Array to hold an instruction encoding.  */
long output_opcode[2];

/* Nonzero means a relocatable symbol.  */
int relocatable;

/* A copy of the original instruction (used in error messages).  */
char ins_parse[MAX_INST_LEN];

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

struct option md_longopts[] =
{
  {NULL, no_argument, NULL, 0}
};
size_t md_longopts_size = sizeof (md_longopts);

const pseudo_typeS md_pseudo_table[] = {};

