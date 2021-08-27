/* BFD back-end for SPC700 binaries.
   Copyright (C) 2005-2018 Free Software Foundation, Inc.
   Contributed by Mads Elvheim <arnold_m@operamail.com>

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "bfdlink.h"
#include "coff/spc700.h"
#include "coff/internal.h"
#include "libcoff.h"

#define COFF_DEFAULT_SECTION_ALIGNMENT_POWER 0

/*
  uint32_t addr = arlent->address + arlent->addend;
  //do stuff with addr according to arlen->howto here
  addr = (addr >> howto->right_shift) << howto->left_shift;
  //perform range checking here according to howto->complain_on_overflow
  uint16_t final_insn = (final_insn&howto->src_mask) | addr;
*/

#if 0
static reloc_howto_type howto_table[] = {
  HOWTO (
    R_SPC700_TCALL_DISP4,       /* The type of the relocation. The linker might be interested in the type when resolving undefined symbols or doing relaxing */
    0,                          /* The number of bits to right-shift the final address by. Use this to finely adjust the final encoding of the instruction. */
    0,                          /* The size of the data we're working on */
    4,                          /* The number of bits in our data */
    FALSE,                      /* Is our relocation type PC-relative? */
    0,                          /* The amount to left-shift the final value by. Use this to finely adjust the final encoding of the instruction. */
    complain_overflow_bitfield, /* If the relocation computation overflows, is that an error we should complain about? */
                                /* This must be one of the enums complain_overflow_bitfield, complain_overflow_signed, complain_overflow_unsigned and complain_overflow_dont */
    0,                          /* If provided (not 0), a function pointer to a custom relocation routine. */
    "r_spc700_disp4",           /* A human-readable name for our relocation type */
    FALSE,                      /* Store addends in relocation info or in the section contents? (Stored in relocation info = FALSE) */
    0x0000000f,                 /* Source mask */
    0xfffffff0,                 /* Destination mask */
    FALSE),                     /* PC relative offset */
  HOWTO (R_SPC700_PCALL_DISP8, 0, 0,  8, FALSE, 0, complain_overflow_dont, 0, "r_imm32", TRUE, 0xffffffff, 0xffffffff, FALSE),
  HOWTO (R_SPC700_IMM8,        0, 0,  8, FALSE, 0, complain_overflow_dont, 0, "r_imm32", TRUE, 0xffffffff, 0xffffffff, FALSE),
  HOWTO (R_SPC700_ABS8,        0, 0,  8, FALSE, 0, complain_overflow_dont, 0, "r_imm32", TRUE, 0xffffffff, 0xffffffff, FALSE),
  HOWTO (R_SPC700_ABS16,       0, 1, 16, FALSE, 0, complain_overflow_dont, 0, "r_imm32", TRUE, 0xffffffff, 0xffffffff, FALSE),
  HOWTO (R_SPC700_PCR8,        0, 0,  8, TRUE,  0, complain_overflow_dont, 0, "r_imm32", TRUE, 0xffffffff, 0xffffffff, FALSE),
  HOWTO (R_SPC700_DPLO8,       0, 0,  8, FALSE, 0, complain_overflow_dont, 0, "r_imm32", TRUE, 0xffffffff, 0xffffffff, FALSE),
  HOWTO (R_SPC700_DPHI8,       0, 0,  8, FALSE, 0, complain_overflow_dont, 0, "r_imm32", TRUE, 0xffffffff, 0xffffffff, FALSE)
};
#endif

static reloc_howto_type howto_table[] = {
  HOWTO (R_SPC700_ABS8,        0, 0,  8, FALSE, 0, complain_overflow_dont, 0, "r_imm32", TRUE, 0xffffffff, 0xffffffff, FALSE),
  HOWTO (R_SPC700_ABS16,       0, 1, 16, FALSE, 0, complain_overflow_dont, 0, "r_imm32", TRUE, 0xffffffff, 0xffffffff, FALSE)
};


#define BADMAG(x) SPC700BADMAG(x)
#define SPC700 1			/* Customize coffcode.h.  */
#define __A_MAGIC_SET__

/* Code to swap in the reloc.  */

#define SWAP_IN_RELOC_OFFSET	H_GET_32
#define SWAP_OUT_RELOC_OFFSET	H_PUT_32

#define SWAP_OUT_RELOC_EXTRA(abfd, src, dst) \
  dst->r_stuff[0] = 'S'; \
  dst->r_stuff[1] = 'C';

/* Code to turn a r_type into a howto ptr, uses the above howto table.  */

static void rtype2howto (arelent *internal, struct internal_reloc *dst){
  int index = dst->r_type;
  if(index < 0){
    internal->howto = NULL;
    return;
  }
  switch(index){
    case R_SPC700_ABS8: internal->howto = &howto_table[0]; return;
    case R_SPC700_ABS16: internal->howto = &howto_table[1]; return;
  }
}

#define RTYPE2HOWTO(internal, relocentry) rtype2howto (internal, relocentry)

static reloc_howto_type * coff_spc700_reloc_type_lookup(bfd *abfd ATTRIBUTE_UNUSED, bfd_reloc_code_real_type code){
  switch (code){
    case BFD_RELOC_8:		return &howto_table[0];
    case BFD_RELOC_16:		return &howto_table[1];
    default:			BFD_FAIL ();
      return NULL;
    }
}

static reloc_howto_type *
coff_spc700_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			    const char *r_name)
{

  for(unsigned int i = 0; i < (sizeof(howto_table) / sizeof(howto_table[0])); i++){
    if (strcasecmp (howto_table[i].name, r_name) == 0){
      return &howto_table[i];
    }
  }
  return NULL;
}

/* Perform any necessary magic to the addend in a reloc entry.  */

#define CALC_ADDEND(abfd, symbol, ext_reloc, cache_ptr) \
 cache_ptr->addend =  ext_reloc.r_offset;

#define RELOC_PROCESSING(relent,reloc,symbols,abfd,section) \
 reloc_processing(relent, reloc, symbols, abfd, section)













static void reloc_processing(arelent *relent, struct internal_reloc *reloc, asymbol **symbols, bfd *abfd, asection *section){
  relent->address = reloc->r_vaddr;
  rtype2howto (relent, reloc);

  if (reloc->r_symndx > 0){
    relent->sym_ptr_ptr = symbols + obj_convert (abfd)[reloc->r_symndx];
  } else {
    relent->sym_ptr_ptr = bfd_abs_section_ptr->symbol_ptr_ptr;
  }

  relent->addend = reloc->r_offset;
  relent->address -= section->vma;
}



/*
  The intersting bits:

  arelent *reloc            The relocation to performed
  bfd_byte *data            The raw data of the output section
  unsigned int *src_ptr     The read pointer into the raw data of the input section. Increment/decrement this to tell the linker how much we advance the reader
  unsigned int *dst_ptr     The read pointer into the raw data of the output section. Increment/decrement this to tell the linker how much we advance the writer
*/
static void extra_case(bfd *in_abfd, struct bfd_link_info *link_info, struct bfd_link_order *link_order, arelent *reloc, bfd_byte *data, unsigned int *src_ptr, unsigned int *dst_ptr){
  asection * input_section = link_order->u.indirect.section;
  int val;

  switch (reloc->howto->type){
    case R_OFF8: {
      val = bfd_coff_reloc16_get_value (reloc, link_info, input_section);
      if (val>127 || val<-128){ /* Test for overflow.  */
	       (*link_info->callbacks->reloc_overflow)(link_info, NULL, bfd_asymbol_name (*reloc->sym_ptr_ptr), reloc->howto->name, reloc->addend, input_section->owner, input_section, reloc->address);
       }
       bfd_put_8 (in_abfd, val, data + *dst_ptr);
       (*dst_ptr) += 1;
       (*src_ptr) += 1;
     }
     break;

    case R_IMM8: {
      val = bfd_get_8 ( in_abfd, data+*src_ptr) + bfd_coff_reloc16_get_value (reloc, link_info, input_section);
      bfd_put_8 (in_abfd, val, data + *dst_ptr);
      (*dst_ptr) += 1;
      (*src_ptr) += 1;
    }
    break;

    case R_IMM16: {
      val = bfd_get_16 ( in_abfd, data+*src_ptr) + bfd_coff_reloc16_get_value (reloc, link_info, input_section);
      bfd_put_16 (in_abfd, val, data + *dst_ptr);
      (*dst_ptr) += 2;
      (*src_ptr) += 2;
    }
    break;

    default: {
      abort ();
    }
  }
}

#define coff_reloc16_extra_cases    extra_case
#define coff_bfd_reloc_type_lookup  coff_spc700_reloc_type_lookup
#define coff_bfd_reloc_name_lookup coff_spc700_reloc_name_lookup

#ifndef bfd_pe_print_pdata
#define bfd_pe_print_pdata	NULL
#endif

#include "coffcode.h"

#undef  coff_bfd_get_relocated_section_contents
#define coff_bfd_get_relocated_section_contents \
  bfd_coff_reloc16_get_relocated_section_contents

#undef  coff_bfd_relax_section
#define coff_bfd_relax_section bfd_coff_reloc16_relax_section

/* TODO: set first 0 to BFD_IS_RELAXABLE and implement int reloc16_estimate (abfd, input_section, reloc, shrink, link_info) to perform linker relaxing */
CREATE_LITTLE_COFF_TARGET_VEC (spc700_coff_vec, "coff-spc700", 0, 0, '_', NULL, COFF_SWAP_TABLE)
