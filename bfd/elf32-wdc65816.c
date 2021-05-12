/* 65816-specific support for 32-bit ELF
   Copyright (C) 1999-2021 Free Software Foundation, Inc.
   Contributed by Denis Chertykov <denisc@overta.ru>

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
   Foundation, Inc., 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"

#include "elf/w65.h"

static reloc_howto_type elf_wdc65816_howto_table[] =
{
	 HOWTO (R_WDC65816_NONE,		/* type */
	 0,			/* rightshift */
	 3,			/* size (0 = byte, 1 = short, 2 = long) */
	 0,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WDC65816_NONE",		/* name */
	 false,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 false),		/* pcrel_offset */
	 HOWTO (R_WDC65816_ABS24,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 24,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WDC65816_ABS24",		/* name */
	 false,			/* partial_inplace */
	 0xffffff,			/* src_mask */
	 0xffffff,			/* dst_mask */
	 false),		/* pcrel_offset */
	 HOWTO (R_WDC65816_ABS16,		/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WDC65816_ABS16",		/* name */
	 false,			/* partial_inplace */
	 0xffff,			/* src_mask */
	 0xffff,			/* dst_mask */
	 false),		/* pcrel_offset */
	HOWTO (R_WDC65816_ABS8,		/* type */
	 0,			/* rightshift */
	 0,			/* size (0 = byte, 1 = short, 2 = long) */
	 8,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WDC65816_ABS8",		/* name */
	 false,			/* partial_inplace */
	 0xff,			/* src_mask */
	 0xff,			/* dst_mask */
	 false),		/* pcrel_offset */
	HOWTO (R_WDC65816_REL8,		/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 8,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WDC65816_REL8",		/* name */
	 false,			/* partial_inplace */
	 0xffffff,			/* src_mask */
	 0xffffff,			/* dst_mask */
	 true),		/* pcrel_offset */
	HOWTO (R_WDC65816_REL8,		/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 8,			/* bitsize */
	 true,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WDC65816_REL8",		/* name */
	 false,			/* partial_inplace */
	 0xffffff,			/* src_mask */
	 0xffffff,			/* dst_mask */
	 true),		/* pcrel_offset */
	HOWTO (R_WDC65816_DIR,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WDC65816_DIR",		/* name */
	 false,			/* partial_inplace */
	 0xff00,			/* src_mask */
	 0xff00,			/* dst_mask */
	 false),		/* pcrel_offset */
	 HOWTO (R_WDC65816_BANK,		/* type */
	 16,			/* rightshift */
	 0,			/* size (0 = byte, 1 = short, 2 = long) */
	 8,			/* bitsize */
	 false,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WDC65816_BANK",		/* name */
	 false,			/* partial_inplace */
	 0xffffff,			/* src_mask */
	 0xffffff,			/* dst_mask */
	 false),		/* pcrel_offset */
};

struct wdc65816_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned int elf_reloc_val;
};

static const struct wdc65816_reloc_map wdc65816_reloc_map[] = {
    {BFD_RELOC_NONE,R_WDC65816_NONE},
	{BFD_RELOC_24,R_WDC65816_ABS24},
	{BFD_RELOC_16,R_WDC65816_ABS16},
	{BFD_RELOC_8,R_WDC65816_ABS8},
	{BFD_RELOC_8_PCREL,R_WDC65816_REL8},
	{BFD_RELOC_16_PCREL,R_WDC65816_REL16},
	{BFD_RELOC_WDC65816_BANK,R_WDC65816_BANK},
	{BFD_RELOC_WDC65816_DIR,R_WDC65816_DIR},
};


static const struct bfd_elf_special_section elf_wdc65816_special_sections[] =
{
	{ STRING_COMMA_LEN(".uninit"),-1,SHT_NOBITS,SHF_ALLOC + SHF_WRITE},
	{NULL, 0, 0, 0, 0}
};


static reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 bfd_reloc_code_real_type code)
{
  unsigned int i;

  for (i = 0;
       i < sizeof (wdc65816_reloc_map) / sizeof (struct wdc65816_reloc_map);
       i++)
    if (wdc65816_reloc_map[i].bfd_reloc_val == code)
      return &elf_wdc65816_howto_table[wdc65816_reloc_map[i].elf_reloc_val];

  return NULL;
}

static reloc_howto_type *
bfd_elf32_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < sizeof (elf_wdc65816_howto_table) / sizeof (elf_wdc65816_howto_table[0]);
       i++)
    if (elf_wdc65816_howto_table[i].name != NULL
	&& strcasecmp (elf_wdc65816_howto_table[i].name, r_name) == 0)
      return &elf_wdc65816_howto_table[i];

  return NULL;
}




/* Perform a single relocation.  By default we use the standard BFD
   routines, but a few relocs, we have to do them ourselves.  */

static bfd_reloc_status_type
wdc65816_final_link_relocate (reloc_howto_type *		    howto,
			 bfd *				    input_bfd,
			 asection *			    input_section,
			 bfd_byte *			    contents,
			 Elf_Internal_Rela *		    rel,
			 bfd_vma			    relocation)
{
  bfd_reloc_status_type r = bfd_reloc_ok;
  bfd_vma reloc_addr;

  /* Absolute addr of the reloc in the final excecutable.  */
  reloc_addr = rel->r_offset + input_section->output_section->vma
	       + input_section->output_offset;\

   (void)reloc_addr;

  switch (howto->type)
    {
    default:
      r = _bfd_final_link_relocate (howto, input_bfd, input_section,
				    contents, rel->r_offset,
				    relocation, rel->r_addend);
    }

  return r;
}

/* Relocate an WDC65816 ELF section.  */

static int
elf32_wdc65816_relocate_section (bfd *output_bfd ATTRIBUTE_UNUSED,
			    struct bfd_link_info *info,
			    bfd *input_bfd,
			    asection *input_section,
			    bfd_byte *contents,
			    Elf_Internal_Rela *relocs,
			    Elf_Internal_Sym *local_syms,
			    asection **local_sections)
{
  Elf_Internal_Shdr *		symtab_hdr;
  struct elf_link_hash_entry ** sym_hashes;
  Elf_Internal_Rela *		rel;
  Elf_Internal_Rela *		relend;


  symtab_hdr = & elf_tdata (input_bfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (input_bfd);
  relend     = relocs + input_section->reloc_count;

  for (rel = relocs; rel < relend; rel ++)
    {
      reloc_howto_type *	   howto;
      unsigned long		   r_symndx;
      Elf_Internal_Sym *	   sym;
      asection *		   sec;
      struct elf_link_hash_entry * h;
      bfd_vma			   relocation;
      bfd_reloc_status_type	   r;
      const char *		   name;
      int			   r_type;

      r_type = ELF32_R_TYPE (rel->r_info);
      r_symndx = ELF32_R_SYM (rel->r_info);
      howto  = elf_wdc65816_howto_table + r_type;
      h      = NULL;
      sym    = NULL;
      sec    = NULL;

      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections [r_symndx];
	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);

	  name = bfd_elf_string_from_elf_section
	    (input_bfd, symtab_hdr->sh_link, sym->st_name);
	  name = name == NULL ? bfd_section_name (sec) : name;
	}
      else
	{
	  bool unresolved_reloc, warned, ignored;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);

	  name = h->root.root.string;
	}

      if (sec != NULL && discarded_section (sec))
	RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
					 rel, 1, relend, howto, 0, contents);

      if (bfd_link_relocatable (info))
	continue;

      r = wdc65816_final_link_relocate (howto, input_bfd, input_section,
				   contents, rel, relocation);

      if (r != bfd_reloc_ok)
	{
	  const char * msg = (const char *) NULL;

	  switch (r)
	    {
	    case bfd_reloc_overflow:
	      (*info->callbacks->reloc_overflow)
		(info, (h ? &h->root : NULL), name, howto->name,
		 (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	      break;

	    case bfd_reloc_undefined:
	      (*info->callbacks->undefined_symbol)
		(info, name, input_bfd, input_section, rel->r_offset, true);
	      break;

	    case bfd_reloc_outofrange:
	      msg = _("internal error: out of range error");
	      break;

	    case bfd_reloc_notsupported:
	      msg = _("internal error: unsupported relocation error");
	      break;

	    case bfd_reloc_dangerous:
	      msg = _("internal error: dangerous relocation");
	      break;

	    default:
	      msg = _("internal error: unknown error");
	      break;
	    }

	  if (msg)
	    (*info->callbacks->warning) (info, msg, name, input_bfd,
					 input_section, rel->r_offset);
	}
    }

  return true;
}

/* The final processing done just before writing out a AVR ELF object
   file.  This gets the AVR architecture right based on the machine
   number.  */

static bool
bfd_elf_wdc65816_final_write_processing (bfd *abfd)
{
  elf_elfheader (abfd)->e_machine = EM_65816;
  return _bfd_elf_final_write_processing (abfd);
}


static bool
elf32_wdc65816_object_p (bfd *abfd){
	elf_elfheader(abfd)->e_machine = EM_65816;
	return true;
}

static bool
wdc65816_info_to_howto_rela (bfd *abfd,
			arelent *cache_ptr,
			Elf_Internal_Rela *dst)
{
  unsigned int r_type;

  r_type = ELF32_R_TYPE (dst->r_info);
  if (r_type >= (unsigned int) R_WDC65816_MAX)
    {
      /* xgettext:c-format */
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return false;
    }
  cache_ptr->howto = &elf_wdc65816_howto_table[r_type];
  return true;
}


/* This is a version of bfd_generic_get_relocated_section_contents
   which uses elf32_wdc65816_relocate_section.

   For wdc65816 it's essentially a cut and paste taken from the avr port.
   The author of the relaxation support patch for wdc65816 had absolutely no
   clue what is happening here but found out that this part of the code
   seems to be important.  */

static bfd_byte *
elf32_wdc65816_get_relocated_section_contents (bfd *output_bfd,
					  struct bfd_link_info *link_info,
					  struct bfd_link_order *link_order,
					  bfd_byte *data,
					  bool relocatable,
					  asymbol **symbols)
{
  Elf_Internal_Shdr *symtab_hdr;
  asection *input_section = link_order->u.indirect.section;
  bfd *input_bfd = input_section->owner;
  asection **sections = NULL;
  Elf_Internal_Rela *internal_relocs = NULL;
  Elf_Internal_Sym *isymbuf = NULL;

  /* We only need to handle the case of relaxing, or of having a
     particular set of section contents, specially.  */
  if (relocatable
      || elf_section_data (input_section)->this_hdr.contents == NULL)
    return bfd_generic_get_relocated_section_contents (output_bfd, link_info,
						       link_order, data,
						       relocatable,
						       symbols);
  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;

  memcpy (data, elf_section_data (input_section)->this_hdr.contents,
	  (size_t) input_section->size);

  if ((input_section->flags & SEC_RELOC) != 0
      && input_section->reloc_count > 0)
    {
      asection **secpp;
      Elf_Internal_Sym *isym, *isymend;
      bfd_size_type amt;

      internal_relocs = (_bfd_elf_link_read_relocs
			 (input_bfd, input_section, NULL, NULL, false));
      if (internal_relocs == NULL)
	goto error_return;

      if (symtab_hdr->sh_info != 0)
	{
	  isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
	  if (isymbuf == NULL)
	    isymbuf = bfd_elf_get_elf_syms (input_bfd, symtab_hdr,
					    symtab_hdr->sh_info, 0,
					    NULL, NULL, NULL);
	  if (isymbuf == NULL)
	    goto error_return;
	}

      amt = symtab_hdr->sh_info;
      amt *= sizeof (asection *);
      sections = bfd_malloc (amt);
      if (sections == NULL && amt != 0)
	goto error_return;

      isymend = isymbuf + symtab_hdr->sh_info;
      for (isym = isymbuf, secpp = sections; isym < isymend; ++isym, ++secpp)
	{
	  asection *isec;

	  if (isym->st_shndx == SHN_UNDEF)
	    isec = bfd_und_section_ptr;
	  else if (isym->st_shndx == SHN_ABS)
	    isec = bfd_abs_section_ptr;
	  else if (isym->st_shndx == SHN_COMMON)
	    isec = bfd_com_section_ptr;
	  else
	    isec = bfd_section_from_elf_index (input_bfd, isym->st_shndx);

	  *secpp = isec;
	}

      if (! elf32_wdc65816_relocate_section (output_bfd, link_info, input_bfd,
					input_section, data, internal_relocs,
					isymbuf, sections))
	goto error_return;

      free (sections);
      if (symtab_hdr->contents != (unsigned char *) isymbuf)
	free (isymbuf);
      if (elf_section_data (input_section)->relocs != internal_relocs)
	free (internal_relocs);
    }

  return data;

 error_return:
  free (sections);
  if (symtab_hdr->contents != (unsigned char *) isymbuf)
    free (isymbuf);
  if (elf_section_data (input_section)->relocs != internal_relocs)
    free (internal_relocs);
  return NULL;
}

// static _Bool w65_new_section_hook(bfd * abfd ATTRIBUTE_UNUSED, sec_ptr ptr ATTRIBUTE_UNUSED){
// 	return true;
// }




#define ELF_ARCH		bfd_arch_w65
#define ELF_TARGET_ID		WDC65816_ELF_DATA
#define ELF_MACHINE_CODE	EM_65816
#define ELF_MAXPAGESIZE		4096

#define TARGET_LITTLE_SYM	wdc65816_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-w65"

#define bfd_elf32_bfd_link_hash_table_create NULL

#define elf_info_to_howto		     wdc65816_info_to_howto_rela
#define elf_info_to_howto_rel		     NULL
#define elf_backend_relocate_section	     elf32_wdc65816_relocate_section
#define elf_backend_can_gc_sections	     1
#define elf_backend_rela_normal		     1
#define elf_backend_final_write_processing \
					bfd_elf_wdc65816_final_write_processing
#define elf_backend_object_p		elf32_wdc65816_object_p

#define bfd_elf32_bfd_get_relocated_section_contents \
					elf32_wdc65816_get_relocated_section_contents
// #define bfd_elf32_new_section_hook	w65_new_section_hook
#define elf_backend_special_sections	elf_wdc65816_special_sections

#include "elf32-target.h"
