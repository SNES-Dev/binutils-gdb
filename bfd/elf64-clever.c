/* Clever specific support for ELF
   Copyright (C) 20921 Connor Horman

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


#include "dwarf2.h"
#include "libiberty.h"

#include "elf/clever.h"

#ifdef CORE_HEADER
#include <stdarg.h>
#include CORE_HEADER
#endif

/* In case we're on a 32-bit machine, construct a 64-bit "-1" value.  */
#define MINUS_ONE (~ (bfd_vma) 0)

/* Since both 32-bit and 64-bit x86-64 encode relocation type in the
   identical manner, we use ELF32_R_TYPE instead of ELF64_R_TYPE to get
   relocation type.  We also use ELF_ST_TYPE instead of ELF64_ST_TYPE
   since they are the same.  */

/* The relocation "howto" table.  Order of fields:
   type, rightshift, size, bitsize, pc_relative, bitpos, complain_on_overflow,
   special_function, name, partial_inplace, src_mask, dst_mask, pcrel_offset.  */
static reloc_howto_type clever_elf_howto_table[] =
{

};


/* Map BFD relocs to the x86_64 elf relocs.  */
struct elf_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned char elf_reloc_val;
};

static const struct elf_reloc_map clever_reloc_map[] =
{

};

static reloc_howto_type *
elf_clever_rtype_to_howto (bfd *abfd, unsigned r_type)
{
  unsigned i;

  BFD_ASSERT (x86_64_elf_howto_table[i].type == r_type);
  return &x86_64_elf_howto_table[i];
}

/* Given a BFD reloc type, return a HOWTO structure.  */
static reloc_howto_type *
elf_clever_reloc_type_lookup (bfd *abfd,
			      bfd_reloc_code_real_type code)
{
  unsigned int i;

  for (i = 0; i < sizeof (clever_reloc_map) / sizeof (struct elf_reloc_map);
       i++)
    {
      if (clever_reloc_map[i].bfd_reloc_val == code)
	return elf_clever_rtype_to_howto (abfd,
					  clever_reloc_map[i].elf_reloc_val);
    }
  return NULL;
}

static reloc_howto_type *
elf_clever_reloc_name_lookup (bfd *abfd,
			      const char *r_name)
{
  unsigned int i;

  for (i = 0; i < ARRAY_SIZE (clever_elf_howto_table); i++)
    if (clever_elf_howto_table[i].name != NULL
	&& strcasecmp (clever_elf_howto_table[i].name, r_name) == 0)
      return &clever_elf_howto_table[i];

  return NULL;
}

/* Given an x86_64 ELF reloc type, fill in an arelent structure.  */

static bool
elf_clever_info_to_howto (bfd *abfd, arelent *cache_ptr,
			  Elf_Internal_Rela *dst)
{
  unsigned r_type;

  r_type = ELF32_R_TYPE (dst->r_info);
  cache_ptr->howto = elf_clever_rtype_to_howto (abfd, r_type);
  if (cache_ptr->howto == NULL)
    return false;
  BFD_ASSERT (r_type == cache_ptr->howto->type || cache_ptr->howto->type == R_X86_64_NONE);
  return true;
}

/* Support for core dump NOTE sections.  */
static bool
elf_clever_grok_prstatus (bfd *abfd, Elf_Internal_Note *note)
{
  int offset;
  size_t size;

  switch (note->descsz)
    {
      default:
	return false;

      case 296:		/* sizeof(istruct elf_prstatus) on Linux/x32 */
	/* pr_cursig */
	elf_tdata (abfd)->core->signal = bfd_get_16 (abfd, note->descdata + 12);

	/* pr_pid */
	elf_tdata (abfd)->core->lwpid = bfd_get_32 (abfd, note->descdata + 24);

	/* pr_reg */
	offset = 72;
	size = 216;

	break;

      case 336:		/* sizeof(istruct elf_prstatus) on Linux/x86_64 */
	/* pr_cursig */
	elf_tdata (abfd)->core->signal
	  = bfd_get_16 (abfd, note->descdata + 12);

	/* pr_pid */
	elf_tdata (abfd)->core->lwpid
	  = bfd_get_32 (abfd, note->descdata + 32);

	/* pr_reg */
	offset = 112;
	size = 216;

	break;
    }

  /* Make a ".reg/999" section.  */
  return _bfd_elfcore_make_pseudosection (abfd, ".reg",
					  size, note->descpos + offset);
}

static bool
elf_clever_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
      default:
	return false;

      case 124:		/* sizeof(struct elf_prpsinfo) on Linux/x32 */
	elf_tdata (abfd)->core->pid
	  = bfd_get_32 (abfd, note->descdata + 12);
	elf_tdata (abfd)->core->program
	  = _bfd_elfcore_strndup (abfd, note->descdata + 28, 16);
	elf_tdata (abfd)->core->command
	  = _bfd_elfcore_strndup (abfd, note->descdata + 44, 80);
	break;

      case 136:		/* sizeof(struct elf_prpsinfo) on Linux/x86_64 */
	elf_tdata (abfd)->core->pid
	  = bfd_get_32 (abfd, note->descdata + 24);
	elf_tdata (abfd)->core->program
	 = _bfd_elfcore_strndup (abfd, note->descdata + 40, 16);
	elf_tdata (abfd)->core->command
	 = _bfd_elfcore_strndup (abfd, note->descdata + 56, 80);
    }

  /* Note that for some reason, a spurious space is tacked
     onto the end of the args in some (at least one anyway)
     implementations, so strip it off if it exists.  */

  {
    char *command = elf_tdata (abfd)->core->command;
    int n = strlen (command);

    if (0 < n && command[n - 1] == ' ')
      command[n - 1] = '\0';
  }

  return true;
}

#ifdef CORE_HEADER
# if GCC_VERSION >= 8000
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wstringop-truncation"
# endif
static char *
elf_x86_64_write_core_note (bfd *abfd, char *buf, int *bufsiz,
			    int note_type, ...)
{
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  va_list ap;
  const char *fname, *psargs;
  long pid;
  int cursig;
  const void *gregs;

  switch (note_type)
    {
    default:
      return NULL;

    case NT_PRPSINFO:
      va_start (ap, note_type);
      fname = va_arg (ap, const char *);
      psargs = va_arg (ap, const char *);
      va_end (ap);

      if (bed->s->elfclass == ELFCLASS32)
	{
	  prpsinfo32_t data;
	  memset (&data, 0, sizeof (data));
	  strncpy (data.pr_fname, fname, sizeof (data.pr_fname));
	  strncpy (data.pr_psargs, psargs, sizeof (data.pr_psargs));
	  return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				     &data, sizeof (data));
	}
      else
	{
	  prpsinfo64_t data;
	  memset (&data, 0, sizeof (data));
	  strncpy (data.pr_fname, fname, sizeof (data.pr_fname));
	  strncpy (data.pr_psargs, psargs, sizeof (data.pr_psargs));
	  return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				     &data, sizeof (data));
	}
      /* NOTREACHED */

    case NT_PRSTATUS:
      va_start (ap, note_type);
      pid = va_arg (ap, long);
      cursig = va_arg (ap, int);
      gregs = va_arg (ap, const void *);
      va_end (ap);

      if (bed->s->elfclass == ELFCLASS32)
	{
	  if (bed->elf_machine_code == EM_X86_64)
	    {
	      prstatusx32_t prstat;
	      memset (&prstat, 0, sizeof (prstat));
	      prstat.pr_pid = pid;
	      prstat.pr_cursig = cursig;
	      memcpy (&prstat.pr_reg, gregs, sizeof (prstat.pr_reg));
	      return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
					 &prstat, sizeof (prstat));
	    }
	  else
	    {
	      prstatus32_t prstat;
	      memset (&prstat, 0, sizeof (prstat));
	      prstat.pr_pid = pid;
	      prstat.pr_cursig = cursig;
	      memcpy (&prstat.pr_reg, gregs, sizeof (prstat.pr_reg));
	      return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
					 &prstat, sizeof (prstat));
	    }
	}
      else
	{
	  prstatus64_t prstat;
	  memset (&prstat, 0, sizeof (prstat));
	  prstat.pr_pid = pid;
	  prstat.pr_cursig = cursig;
	  memcpy (&prstat.pr_reg, gregs, sizeof (prstat.pr_reg));
	  return elfcore_write_note (abfd, buf, bufsiz, "CORE", note_type,
				     &prstat, sizeof (prstat));
	}
    }
  /* NOTREACHED */
}
# if GCC_VERSION >= 8000
#  pragma GCC diagnostic pop
# endif
#endif

/* Functions for the clever ELF linker.	 */

/* The size in bytes of an entry in the global offset table.  */

#define GOT_ENTRY_SIZE 8

/* The size in bytes of an entry in the lazy procedure linkage table.  */

#define LAZY_PLT_ENTRY_SIZE 36

/* The size in bytes of an entry in the non-lazy procedure linkage
   table.  */

#define NON_LAZY_PLT_ENTRY_SIZE 12


/* Subsequent entries in a lazy procedure linkage table look like this.  */

static const bfd_byte elf_clever_lazy_plt_entry[LAZY_PLT_ENTRY_SIZE] =
{
  0x00, 0xab, 0xe6, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov.r11 *name@GOTPCREL(ip)
  0x7c, 0x9b, // ijmp r11
  0x01, 0x40, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, // push 0
  0x00, 0xab, 0xe6, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov.r11 *GOT+16(ip)
  0x7c, 0x9b, // ijmp r11
};


/* Entries in the non-lazey procedure linkage table look like this.  */

static const bfd_byte elf_clever_non_lazy_plt_entry[NON_LAZY_PLT_ENTRY_SIZE] =
{
  0x00, 0xab, 0xe6, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov.r11 *name@GOTPCREL(ip)
  0x7c, 0x9b, // ijmp r11
};


/* .eh_frame covering the lazy .plt section.  */

static const bfd_byte elf_x86_64_eh_frame_lazy_plt[] =
{
  PLT_CIE_LENGTH, 0, 0, 0,	/* CIE length */
  0, 0, 0, 0,			/* CIE ID */
  1,				/* CIE version */
  'z', 'R', 0,			/* Augmentation string */
  1,				/* Code alignment factor */
  0x78,				/* Data alignment factor */
  16,				/* Return address column */
  1,				/* Augmentation size */
  DW_EH_PE_pcrel | DW_EH_PE_sdata4, /* FDE encoding */
  DW_CFA_def_cfa, 7, 8,		/* DW_CFA_def_cfa: r7 (rsp) ofs 8 */
  DW_CFA_offset + 16, 1,	/* DW_CFA_offset: r16 (rip) at cfa-8 */
  DW_CFA_nop, DW_CFA_nop,

  PLT_FDE_LENGTH, 0, 0, 0,	/* FDE length */
  PLT_CIE_LENGTH + 8, 0, 0, 0,	/* CIE pointer */
  0, 0, 0, 0,			/* R_X86_64_PC32 .plt goes here */
  0, 0, 0, 0,			/* .plt size goes here */
  0,				/* Augmentation size */
  DW_CFA_def_cfa_offset, 16,	/* DW_CFA_def_cfa_offset: 16 */
  DW_CFA_advance_loc + 6,	/* DW_CFA_advance_loc: 6 to __PLT__+6 */
  DW_CFA_def_cfa_offset, 24,	/* DW_CFA_def_cfa_offset: 24 */
  DW_CFA_advance_loc + 10,	/* DW_CFA_advance_loc: 10 to __PLT__+16 */
  DW_CFA_def_cfa_expression,	/* DW_CFA_def_cfa_expression */
  11,				/* Block length */
  DW_OP_breg7, 8,		/* DW_OP_breg7 (rsp): 8 */
  DW_OP_breg16, 0,		/* DW_OP_breg16 (rip): 0 */
  DW_OP_lit15, DW_OP_and, DW_OP_lit11, DW_OP_ge,
  DW_OP_lit3, DW_OP_shl, DW_OP_plus,
  DW_CFA_nop, DW_CFA_nop, DW_CFA_nop, DW_CFA_nop
};


/* .eh_frame covering the non-lazy .plt section.  */

static const bfd_byte elf_clever_eh_frame_non_lazy_plt[] =
{
#define PLT_GOT_FDE_LENGTH		20
  PLT_CIE_LENGTH, 0, 0, 0,	/* CIE length */
  0, 0, 0, 0,			/* CIE ID */
  1,				/* CIE version */
  'z', 'R', 0,			/* Augmentation string */
  1,				/* Code alignment factor */
  0x78,				/* Data alignment factor */
  16,				/* Return address column */
  1,				/* Augmentation size */
  DW_EH_PE_pcrel | DW_EH_PE_sdata4, /* FDE encoding */
  DW_CFA_def_cfa, 7, 8,		/* DW_CFA_def_cfa: r7 (rsp) ofs 8 */
  DW_CFA_offset + 16, 1,	/* DW_CFA_offset: r16 (rip) at cfa-8 */
  DW_CFA_nop, DW_CFA_nop,

  PLT_GOT_FDE_LENGTH, 0, 0, 0,	/* FDE length */
  PLT_CIE_LENGTH + 8, 0, 0, 0,	/* CIE pointer */
  0, 0, 0, 0,			/* the start of non-lazy .plt goes here */
  0, 0, 0, 0,			/* non-lazy .plt size goes here */
  0,				/* Augmentation size */
  DW_CFA_nop, DW_CFA_nop, DW_CFA_nop, DW_CFA_nop,
  DW_CFA_nop, DW_CFA_nop, DW_CFA_nop
};

/* These are the standard parameters.  */
static const struct elf_clever_lazy_plt_layout elf_clever_lazy_plt =
  {
    elf_x86_64_lazy_plt0_entry,		/* plt0_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt0_entry_size */
    elf_x86_64_lazy_plt_entry,		/* plt_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    elf_x86_64_tlsdesc_plt_entry,	/* plt_tlsdesc_entry */
    LAZY_PLT_ENTRY_SIZE,		/* plt_tlsdesc_entry_size */
    6,					/* plt_tlsdesc_got1_offset */
    12,					/* plt_tlsdesc_got2_offset */
    10,					/* plt_tlsdesc_got1_insn_end */
    16,					/* plt_tlsdesc_got2_insn_end */
    2,					/* plt0_got1_offset */
    8,					/* plt0_got2_offset */
    12,					/* plt0_got2_insn_end */
    2,					/* plt_got_offset */
    7,					/* plt_reloc_offset */
    12,					/* plt_plt_offset */
    6,					/* plt_got_insn_size */
    LAZY_PLT_ENTRY_SIZE,		/* plt_plt_insn_end */
    6,					/* plt_lazy_offset */
    elf_x86_64_lazy_plt0_entry,		/* pic_plt0_entry */
    elf_x86_64_lazy_plt_entry,		/* pic_plt_entry */
    elf_x86_64_eh_frame_lazy_plt,	/* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_lazy_plt) /* eh_frame_plt_size */
  };

static const struct elf_clever_non_lazy_plt_layout elf_clever_non_lazy_plt =
  {
    elf_x86_64_non_lazy_plt_entry,	/* plt_entry */
    elf_x86_64_non_lazy_plt_entry,	/* pic_plt_entry */
    NON_LAZY_PLT_ENTRY_SIZE,		/* plt_entry_size */
    2,					/* plt_got_offset */
    6,					/* plt_got_insn_size */
    elf_x86_64_eh_frame_non_lazy_plt,	/* eh_frame_plt */
    sizeof (elf_x86_64_eh_frame_non_lazy_plt) /* eh_frame_plt_size */
  };



static bool
elf64_x86_64_elf_object_p (bfd *abfd)
{
  return true;
}

static bool
elf32_x86_64_elf_object_p (bfd *abfd)
{
  return true;
}


/* Rename some of the generic section flags to better document how they
   are used here.  */
#define check_relocs_failed	sec_flg0

static bool
elf_clever_need_pic (struct bfd_link_info *info,
		     bfd *input_bfd, asection *sec,
		     struct elf_link_hash_entry *h,
		     Elf_Internal_Shdr *symtab_hdr,
		     Elf_Internal_Sym *isym,
		     reloc_howto_type *howto)
{
  const char *v = "";
  const char *und = "";
  const char *pic = "";
  const char *object;

  const char *name;
  if (h)
    {
      name = h->root.root.string;
      switch (ELF_ST_VISIBILITY (h->other))
	{
	case STV_HIDDEN:
	  v = _("hidden symbol ");
	  break;
	case STV_INTERNAL:
	  v = _("internal symbol ");
	  break;
	case STV_PROTECTED:
	  v = _("protected symbol ");
	  break;
	default:
	  if (((struct elf_x86_link_hash_entry *) h)->def_protected)
	    v = _("protected symbol ");
	  else
	    v = _("symbol ");
	  pic = NULL;
	  break;
	}

      if (!SYMBOL_DEFINED_NON_SHARED_P (h) && !h->def_dynamic)
	und = _("undefined ");
    }
  else
    {
      name = bfd_elf_sym_name (input_bfd, symtab_hdr, isym, NULL);
      pic = NULL;
    }

  if (bfd_link_dll (info))
    {
      object = _("a shared object");
      if (!pic)
	pic = _("; recompile with -fPIC");
    }
  else
    {
      if (bfd_link_pie (info))
	object = _("a PIE object");
      else
	object = _("a PDE object");
      if (!pic)
	pic = _("; recompile with -fPIE");
    }

  /* xgettext:c-format */
  _bfd_error_handler (_("%pB: relocation %s against %s%s`%s' can "
			"not be used when making %s%s"),
		      input_bfd, howto->name, und, v, name,
		      object, pic);
  bfd_set_error (bfd_error_bad_value);
  sec->check_relocs_failed = 1;
  return false;
}


/* Look through the relocs for a section during the first phase, and
   calculate needed space in the global offset table, procedure
   linkage table, and dynamic reloc sections.  */

static bool
elf_clever_check_relocs (bfd *abfd, struct bfd_link_info *info,
			 asection *sec,
			 const Elf_Internal_Rela *relocs)
{
  struct elf_clever_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  asection *sreloc;
  bfd_byte *contents;
  bool converted;

  if (bfd_link_relocatable (info))
    return true;

  htab = elf_x86_hash_table (info, X86_64_ELF_DATA);
  if (htab == NULL)
    {
      sec->check_relocs_failed = 1;
      return false;
    }

  BFD_ASSERT (is_x86_elf (abfd, htab));

  /* Get the section contents.  */
  if (elf_section_data (sec)->this_hdr.contents != NULL)
    contents = elf_section_data (sec)->this_hdr.contents;
  else if (!bfd_malloc_and_get_section (abfd, sec, &contents))
    {
      sec->check_relocs_failed = 1;
      return false;
    }

  symtab_hdr = &elf_symtab_hdr (abfd);
  sym_hashes = elf_sym_hashes (abfd);

  converted = false;

  sreloc = NULL;

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      unsigned int r_type;
      unsigned int r_symndx;
      struct elf_link_hash_entry *h;
      struct elf_x86_link_hash_entry *eh;
      Elf_Internal_Sym *isym;
      const char *name;
      bool size_reloc;
      bool converted_reloc;
      bool no_dynreloc;

      r_symndx = htab->r_sym (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_symndx >= NUM_SHDR_ENTRIES (symtab_hdr))
	{
	  /* xgettext:c-format */
	  _bfd_error_handler (_("%pB: bad symbol index: %d"),
			      abfd, r_symndx);
	  goto error_return;
	}

      if (r_symndx < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache,
					abfd, r_symndx);
	  if (isym == NULL)
	    goto error_return;

	  /* Check relocation against local STT_GNU_IFUNC symbol.  */
	  if (ELF_ST_TYPE (isym->st_info) == STT_GNU_IFUNC)
	    {
	      h = _bfd_elf_x86_get_local_sym_hash (htab, abfd, rel,
						   true);
	      if (h == NULL)
		goto error_return;

	      /* Fake a STT_GNU_IFUNC symbol.  */
	      h->root.root.string = bfd_elf_sym_name (abfd, symtab_hdr,
						      isym, NULL);
	      h->type = STT_GNU_IFUNC;
	      h->def_regular = 1;
	      h->ref_regular = 1;
	      h->forced_local = 1;
	      h->root.type = bfd_link_hash_defined;
	    }
	  else
	    h = NULL;
	}
      else
	{
	  isym = NULL;
	  h = sym_hashes[r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      /* Check invalid x32 relocations.  */
      if (!ABI_64_P (abfd))
	switch (r_type)
	  {
	  default:
	    break;

	  case R_X86_64_DTPOFF64:
	  case R_X86_64_TPOFF64:
	  case R_X86_64_PC64:
	  case R_X86_64_GOTOFF64:
	  case R_X86_64_GOT64:
	  case R_X86_64_GOTPCREL64:
	  case R_X86_64_GOTPC64:
	  case R_X86_64_GOTPLT64:
	  case R_X86_64_PLTOFF64:
	      {
		if (h)
		  name = h->root.root.string;
		else
		  name = bfd_elf_sym_name (abfd, symtab_hdr, isym,
					   NULL);
		_bfd_error_handler
		  /* xgettext:c-format */
		  (_("%pB: relocation %s against symbol `%s' isn't "
		     "supported in x32 mode"), abfd,
		   x86_64_elf_howto_table[r_type].name, name);
		bfd_set_error (bfd_error_bad_value);
		goto error_return;
	      }
	    break;
	  }

      if (h != NULL)
	{
	  /* It is referenced by a non-shared object. */
	  h->ref_regular = 1;
	}

      converted_reloc = false;
      if ((r_type == R_X86_64_GOTPCREL
	   || r_type == R_X86_64_GOTPCRELX
	   || r_type == R_X86_64_REX_GOTPCRELX)
	  && (h == NULL || h->type != STT_GNU_IFUNC))
	{
	  Elf_Internal_Rela *irel = (Elf_Internal_Rela *) rel;
	  if (!elf_x86_64_convert_load_reloc (abfd, contents, &r_type,
					      irel, h, &converted_reloc,
					      info))
	    goto error_return;

	  if (converted_reloc)
	    converted = true;
	}

      if (!_bfd_elf_x86_valid_reloc_p (sec, info, htab, rel, h, isym,
				       symtab_hdr, &no_dynreloc))
	return false;

      if (! elf_x86_64_tls_transition (info, abfd, sec, contents,
				       symtab_hdr, sym_hashes,
				       &r_type, GOT_UNKNOWN,
				       rel, rel_end, h, r_symndx, false))
	goto error_return;

      /* Check if _GLOBAL_OFFSET_TABLE_ is referenced.  */
      if (h == htab->elf.hgot)
	htab->got_referenced = true;

      eh = (struct elf_x86_link_hash_entry *) h;
      switch (r_type)
	{
	case R_X86_64_TLSLD:
	  htab->tls_ld_or_ldm_got.refcount = 1;
	  goto create_got;

	case R_X86_64_TPOFF32:
	  if (!bfd_link_executable (info) && ABI_64_P (abfd))
	    return elf_x86_64_need_pic (info, abfd, sec, h, symtab_hdr, isym,
					&x86_64_elf_howto_table[r_type]);
	  if (eh != NULL)
	    eh->zero_undefweak &= 0x2;
	  break;

	case R_X86_64_GOTTPOFF:
	  if (!bfd_link_executable (info))
	    info->flags |= DF_STATIC_TLS;
	  /* Fall through */

	case R_X86_64_GOT32:
	case R_X86_64_GOTPCREL:
	case R_X86_64_GOTPCRELX:
	case R_X86_64_REX_GOTPCRELX:
	case R_X86_64_TLSGD:
	case R_X86_64_GOT64:
	case R_X86_64_GOTPCREL64:
	case R_X86_64_GOTPLT64:
	case R_X86_64_GOTPC32_TLSDESC:
	case R_X86_64_TLSDESC_CALL:
	  /* This symbol requires a global offset table entry.	*/
	  {
	    int tls_type, old_tls_type;

	    switch (r_type)
	      {
	      default:
		tls_type = GOT_NORMAL;
		if (h)
		  {
		    if (ABS_SYMBOL_P (h))
		      tls_type = GOT_ABS;
		  }
		else if (isym->st_shndx == SHN_ABS)
		  tls_type = GOT_ABS;
		break;
	      case R_X86_64_TLSGD:
		tls_type = GOT_TLS_GD;
		break;
	      case R_X86_64_GOTTPOFF:
		tls_type = GOT_TLS_IE;
		break;
	      case R_X86_64_GOTPC32_TLSDESC:
	      case R_X86_64_TLSDESC_CALL:
		tls_type = GOT_TLS_GDESC;
		break;
	      }

	    if (h != NULL)
	      {
		h->got.refcount = 1;
		old_tls_type = eh->tls_type;
	      }
	    else
	      {
		bfd_signed_vma *local_got_refcounts;

		/* This is a global offset table entry for a local symbol.  */
		local_got_refcounts = elf_local_got_refcounts (abfd);
		if (local_got_refcounts == NULL)
		  {
		    bfd_size_type size;

		    size = symtab_hdr->sh_info;
		    size *= sizeof (bfd_signed_vma)
		      + sizeof (bfd_vma) + sizeof (char);
		    local_got_refcounts = ((bfd_signed_vma *)
					   bfd_zalloc (abfd, size));
		    if (local_got_refcounts == NULL)
		      goto error_return;
		    elf_local_got_refcounts (abfd) = local_got_refcounts;
		    elf_x86_local_tlsdesc_gotent (abfd)
		      = (bfd_vma *) (local_got_refcounts + symtab_hdr->sh_info);
		    elf_x86_local_got_tls_type (abfd)
		      = (char *) (local_got_refcounts + 2 * symtab_hdr->sh_info);
		  }
		local_got_refcounts[r_symndx] = 1;
		old_tls_type
		  = elf_x86_local_got_tls_type (abfd) [r_symndx];
	      }

	    /* If a TLS symbol is accessed using IE at least once,
	       there is no point to use dynamic model for it.  */
	    if (old_tls_type != tls_type && old_tls_type != GOT_UNKNOWN
		&& (! GOT_TLS_GD_ANY_P (old_tls_type)
		    || tls_type != GOT_TLS_IE))
	      {
		if (old_tls_type == GOT_TLS_IE && GOT_TLS_GD_ANY_P (tls_type))
		  tls_type = old_tls_type;
		else if (GOT_TLS_GD_ANY_P (old_tls_type)
			 && GOT_TLS_GD_ANY_P (tls_type))
		  tls_type |= old_tls_type;
		else
		  {
		    if (h)
		      name = h->root.root.string;
		    else
		      name = bfd_elf_sym_name (abfd, symtab_hdr,
					       isym, NULL);
		    _bfd_error_handler
		      /* xgettext:c-format */
		      (_("%pB: '%s' accessed both as normal and"
			 " thread local symbol"),
		       abfd, name);
		    bfd_set_error (bfd_error_bad_value);
		    goto error_return;
		  }
	      }

	    if (old_tls_type != tls_type)
	      {
		if (eh != NULL)
		  eh->tls_type = tls_type;
		else
		  elf_x86_local_got_tls_type (abfd) [r_symndx] = tls_type;
	      }
	  }
	  /* Fall through */

	case R_X86_64_GOTOFF64:
	case R_X86_64_GOTPC32:
	case R_X86_64_GOTPC64:
	create_got:
	  if (eh != NULL)
	    eh->zero_undefweak &= 0x2;
	  break;

	case R_X86_64_PLT32:
	case R_X86_64_PLT32_BND:
	  /* This symbol requires a procedure linkage table entry.  We
	     actually build the entry in adjust_dynamic_symbol,
	     because this might be a case of linking PIC code which is
	     never referenced by a dynamic object, in which case we
	     don't need to generate a procedure linkage table entry
	     after all.	 */

	  /* If this is a local symbol, we resolve it directly without
	     creating a procedure linkage table entry.	*/
	  if (h == NULL)
	    continue;

	  eh->zero_undefweak &= 0x2;
	  h->needs_plt = 1;
	  h->plt.refcount = 1;
	  break;

	case R_X86_64_PLTOFF64:
	  /* This tries to form the 'address' of a function relative
	     to GOT.  For global symbols we need a PLT entry.  */
	  if (h != NULL)
	    {
	      h->needs_plt = 1;
	      h->plt.refcount = 1;
	    }
	  goto create_got;

	case R_X86_64_SIZE32:
	case R_X86_64_SIZE64:
	  size_reloc = true;
	  goto do_size;

	case R_X86_64_32:
	  if (!ABI_64_P (abfd))
	    goto pointer;
	  /* Fall through.  */
	case R_X86_64_8:
	case R_X86_64_16:
	case R_X86_64_32S:
	  /* Check relocation overflow as these relocs may lead to
	     run-time relocation overflow.  Don't error out for
	     sections we don't care about, such as debug sections or
	     when relocation overflow check is disabled.  */
	  if (!htab->params->no_reloc_overflow_check
	      && !converted_reloc
	      && (bfd_link_pic (info)
		  || (bfd_link_executable (info)
		      && h != NULL
		      && !h->def_regular
		      && h->def_dynamic
		      && (sec->flags & SEC_READONLY) == 0)))
	    return elf_x86_64_need_pic (info, abfd, sec, h, symtab_hdr, isym,
					&x86_64_elf_howto_table[r_type]);
	  /* Fall through.  */

	case R_X86_64_PC8:
	case R_X86_64_PC16:
	case R_X86_64_PC32:
	case R_X86_64_PC32_BND:
	case R_X86_64_PC64:
	case R_X86_64_64:
	pointer:
	  if (eh != NULL && (sec->flags & SEC_CODE) != 0)
	    eh->zero_undefweak |= 0x2;
	  /* We are called after all symbols have been resolved.  Only
	     relocation against STT_GNU_IFUNC symbol must go through
	     PLT.  */
	  if (h != NULL
	      && (bfd_link_executable (info)
		  || h->type == STT_GNU_IFUNC))
	    {
	      bool func_pointer_ref = false;

	      if (r_type == R_X86_64_PC32)
		{
		  /* Since something like ".long foo - ." may be used
		     as pointer, make sure that PLT is used if foo is
		     a function defined in a shared library.  */
		  if ((sec->flags & SEC_CODE) == 0)
		    {
		      h->pointer_equality_needed = 1;
		      if (bfd_link_pie (info)
			  && h->type == STT_FUNC
			  && !h->def_regular
			  && h->def_dynamic)
			{
			  h->needs_plt = 1;
			  h->plt.refcount = 1;
			}
		    }
		}
	      else if (r_type != R_X86_64_PC32_BND
		       && r_type != R_X86_64_PC64)
		{
		  h->pointer_equality_needed = 1;
		  /* At run-time, R_X86_64_64 can be resolved for both
		     x86-64 and x32. But R_X86_64_32 and R_X86_64_32S
		     can only be resolved for x32.  */
		  if ((sec->flags & SEC_READONLY) == 0
		      && (r_type == R_X86_64_64
			  || (!ABI_64_P (abfd)
			      && (r_type == R_X86_64_32
				  || r_type == R_X86_64_32S))))
		    func_pointer_ref = true;
		}

	      if (!func_pointer_ref)
		{
		  /* If this reloc is in a read-only section, we might
		     need a copy reloc.  We can't check reliably at this
		     stage whether the section is read-only, as input
		     sections have not yet been mapped to output sections.
		     Tentatively set the flag for now, and correct in
		     adjust_dynamic_symbol.  */
		  h->non_got_ref = 1;

		  /* We may need a .plt entry if the symbol is a function
		     defined in a shared lib or is a function referenced
		     from the code or read-only section.  */
		  if (!h->def_regular
		      || (sec->flags & (SEC_CODE | SEC_READONLY)) != 0)
		    h->plt.refcount = 1;
		}
	    }

	  size_reloc = false;
	do_size:
	  if (!no_dynreloc
	      && NEED_DYNAMIC_RELOCATION_P (info, true, h, sec, r_type,
					    htab->pointer_r_type))
	    {
	      struct elf_dyn_relocs *p;
	      struct elf_dyn_relocs **head;

	      /* We must copy these reloc types into the output file.
		 Create a reloc section in dynobj and make room for
		 this reloc.  */
	      if (sreloc == NULL)
		{
		  sreloc = _bfd_elf_make_dynamic_reloc_section
		    (sec, htab->elf.dynobj, ABI_64_P (abfd) ? 3 : 2,
		     abfd, /*rela?*/ true);

		  if (sreloc == NULL)
		    goto error_return;
		}

	      /* If this is a global symbol, we count the number of
		 relocations we need for this symbol.  */
	      if (h != NULL)
		head = &h->dyn_relocs;
	      else
		{
		  /* Track dynamic relocs needed for local syms too.
		     We really need local syms available to do this
		     easily.  Oh well.  */
		  asection *s;
		  void **vpp;

		  isym = bfd_sym_from_r_symndx (&htab->elf.sym_cache,
						abfd, r_symndx);
		  if (isym == NULL)
		    goto error_return;

		  s = bfd_section_from_elf_index (abfd, isym->st_shndx);
		  if (s == NULL)
		    s = sec;

		  /* Beware of type punned pointers vs strict aliasing
		     rules.  */
		  vpp = &(elf_section_data (s)->local_dynrel);
		  head = (struct elf_dyn_relocs **)vpp;
		}

	      p = *head;
	      if (p == NULL || p->sec != sec)
		{
		  size_t amt = sizeof *p;

		  p = ((struct elf_dyn_relocs *)
		       bfd_alloc (htab->elf.dynobj, amt));
		  if (p == NULL)
		    goto error_return;
		  p->next = *head;
		  *head = p;
		  p->sec = sec;
		  p->count = 0;
		  p->pc_count = 0;
		}

	      p->count += 1;
	      /* Count size relocation as PC-relative relocation.  */
	      if (X86_PCREL_TYPE_P (r_type) || size_reloc)
		p->pc_count += 1;
	    }
	  break;

	  /* This relocation describes the C++ object vtable hierarchy.
	     Reconstruct it for later use during GC.  */
	case R_X86_64_GNU_VTINHERIT:
	  if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
	    goto error_return;
	  break;

	  /* This relocation describes which C++ vtable entries are actually
	     used.  Record for later use during GC.  */
	case R_X86_64_GNU_VTENTRY:
	  if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
	    goto error_return;
	  break;

	default:
	  break;
	}
    }

  if (elf_section_data (sec)->this_hdr.contents != contents)
    {
      if (!converted && !info->keep_memory)
	free (contents);
      else
	{
	  /* Cache the section contents for elf_link_input_bfd if any
	     load is converted or --no-keep-memory isn't used.  */
	  elf_section_data (sec)->this_hdr.contents = contents;
	}
    }

  /* Cache relocations if any load is converted.  */
  if (elf_section_data (sec)->relocs != relocs && converted)
    elf_section_data (sec)->relocs = (Elf_Internal_Rela *) relocs;

  return true;

 error_return:
  if (elf_section_data (sec)->this_hdr.contents != contents)
    free (contents);
  sec->check_relocs_failed = 1;
  return false;
}

/* Return the relocation value for @tpoff relocation
   if STT_TLS virtual address is ADDRESS.  */

static bfd_vma
elf_x86_64_tpoff (struct bfd_link_info *info, bfd_vma address)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);
  const struct elf_backend_data *bed = get_elf_backend_data (info->output_bfd);
  bfd_vma static_tls_size;

  /* If tls_segment is NULL, we should have signalled an error already.  */
  if (htab->tls_sec == NULL)
    return 0;

  /* Consider special static TLS alignment requirements.  */
  static_tls_size = BFD_ALIGN (htab->tls_size, bed->static_tls_alignment);
  return address - static_tls_size - htab->tls_sec->vma;
}

/* Relocate an x86_64 ELF section.  */

static int
elf_x86_64_relocate_section (bfd *output_bfd,
			     struct bfd_link_info *info,
			     bfd *input_bfd,
			     asection *input_section,
			     bfd_byte *contents,
			     Elf_Internal_Rela *relocs,
			     Elf_Internal_Sym *local_syms,
			     asection **local_sections)
{
  struct elf_x86_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_vma *local_got_offsets;
  bfd_vma *local_tlsdesc_gotents;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *wrel;
  Elf_Internal_Rela *relend;
  unsigned int plt_entry_size;
  bool status;

  /* Skip if check_relocs failed.  */
  if (input_section->check_relocs_failed)
    return false;

  htab = elf_x86_hash_table (info, X86_64_ELF_DATA);
  if (htab == NULL)
    return false;

  if (!is_x86_elf (input_bfd, htab))
    {
      bfd_set_error (bfd_error_wrong_format);
      return false;
    }

  plt_entry_size = htab->plt.plt_entry_size;
  symtab_hdr = &elf_symtab_hdr (input_bfd);
  sym_hashes = elf_sym_hashes (input_bfd);
  local_got_offsets = elf_local_got_offsets (input_bfd);
  local_tlsdesc_gotents = elf_x86_local_tlsdesc_gotent (input_bfd);

  _bfd_x86_elf_set_tls_module_base (info);

  status = true;
  rel = wrel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; wrel++, rel++)
    {
      unsigned int r_type, r_type_tls;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      struct elf_link_hash_entry *h;
      struct elf_x86_link_hash_entry *eh;
      Elf_Internal_Sym *sym;
      asection *sec;
      bfd_vma off, offplt, plt_offset;
      bfd_vma relocation;
      bool unresolved_reloc;
      bfd_reloc_status_type r;
      int tls_type;
      asection *base_got, *resolved_plt;
      bfd_vma st_size;
      bool resolved_to_zero;
      bool relative_reloc;
      bool converted_reloc;
      bool need_copy_reloc_in_pie;
      bool no_copyreloc_p;

      r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == (int) R_X86_64_GNU_VTINHERIT
	  || r_type == (int) R_X86_64_GNU_VTENTRY)
	{
	  if (wrel != rel)
	    *wrel = *rel;
	  continue;
	}

      r_symndx = htab->r_sym (rel->r_info);
      converted_reloc = (r_type & R_X86_64_converted_reloc_bit) != 0;
      if (converted_reloc)
	{
	  r_type &= ~R_X86_64_converted_reloc_bit;
	  rel->r_info = htab->r_info (r_symndx, r_type);
	}

      howto = elf_x86_64_rtype_to_howto (input_bfd, r_type);
      if (howto == NULL)
	return _bfd_unrecognized_reloc (input_bfd, input_section, r_type);

      h = NULL;
      sym = NULL;
      sec = NULL;
      unresolved_reloc = false;
      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];

	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym,
						&sec, rel);
	  st_size = sym->st_size;

	  /* Relocate against local STT_GNU_IFUNC symbol.  */
	  if (!bfd_link_relocatable (info)
	      && ELF_ST_TYPE (sym->st_info) == STT_GNU_IFUNC)
	    {
	      h = _bfd_elf_x86_get_local_sym_hash (htab, input_bfd,
						   rel, false);
	      if (h == NULL)
		abort ();

	      /* Set STT_GNU_IFUNC symbol value.  */
	      h->root.u.def.value = sym->st_value;
	      h->root.u.def.section = sec;
	    }
	}
      else
	{
	  bool warned ATTRIBUTE_UNUSED;
	  bool ignored ATTRIBUTE_UNUSED;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned, ignored);
	  st_size = h->size;
	}

      if (sec != NULL && discarded_section (sec))
	{
	  _bfd_clear_contents (howto, input_bfd, input_section,
			       contents, rel->r_offset);
	  wrel->r_offset = rel->r_offset;
	  wrel->r_info = 0;
	  wrel->r_addend = 0;

	  /* For ld -r, remove relocations in debug sections against
	     sections defined in discarded sections.  Not done for
	     eh_frame editing code expects to be present.  */
	   if (bfd_link_relocatable (info)
	       && (input_section->flags & SEC_DEBUGGING))
	     wrel--;

	  continue;
	}

      if (bfd_link_relocatable (info))
	{
	  if (wrel != rel)
	    *wrel = *rel;
	  continue;
	}

      if (rel->r_addend == 0 && !ABI_64_P (output_bfd))
	{
	  if (r_type == R_X86_64_64)
	    {
	      /* For x32, treat R_X86_64_64 like R_X86_64_32 and
		 zero-extend it to 64bit if addend is zero.  */
	      r_type = R_X86_64_32;
	      memset (contents + rel->r_offset + 4, 0, 4);
	    }
	  else if (r_type == R_X86_64_SIZE64)
	    {
	      /* For x32, treat R_X86_64_SIZE64 like R_X86_64_SIZE32 and
		 zero-extend it to 64bit if addend is zero.  */
	      r_type = R_X86_64_SIZE32;
	      memset (contents + rel->r_offset + 4, 0, 4);
	    }
	}

      eh = (struct elf_x86_link_hash_entry *) h;

      /* Since STT_GNU_IFUNC symbol must go through PLT, we handle
	 it here if it is defined in a non-shared object.  */
      if (h != NULL
	  && h->type == STT_GNU_IFUNC
	  && h->def_regular)
	{
	  bfd_vma plt_index;
	  const char *name;

	  if ((input_section->flags & SEC_ALLOC) == 0)
	    {
	      /* If this is a SHT_NOTE section without SHF_ALLOC, treat
	         STT_GNU_IFUNC symbol as STT_FUNC.  */
	      if (elf_section_type (input_section) == SHT_NOTE)
		goto skip_ifunc;
	      /* Dynamic relocs are not propagated for SEC_DEBUGGING
		 sections because such sections are not SEC_ALLOC and
		 thus ld.so will not process them.  */
	      if ((input_section->flags & SEC_DEBUGGING) != 0)
		continue;
	      abort ();
	    }

	  switch (r_type)
	    {
	    default:
	      break;

	    case R_X86_64_GOTPCREL:
	    case R_X86_64_GOTPCRELX:
	    case R_X86_64_REX_GOTPCRELX:
	    case R_X86_64_GOTPCREL64:
	      base_got = htab->elf.sgot;
	      off = h->got.offset;

	      if (base_got == NULL)
		abort ();

	      if (off == (bfd_vma) -1)
		{
		  /* We can't use h->got.offset here to save state, or
		     even just remember the offset, as finish_dynamic_symbol
		     would use that as offset into .got.  */

		  if (h->plt.offset == (bfd_vma) -1)
		    abort ();

		  if (htab->elf.splt != NULL)
		    {
		      plt_index = (h->plt.offset / plt_entry_size
				   - htab->plt.has_plt0);
		      off = (plt_index + 3) * GOT_ENTRY_SIZE;
		      base_got = htab->elf.sgotplt;
		    }
		  else
		    {
		      plt_index = h->plt.offset / plt_entry_size;
		      off = plt_index * GOT_ENTRY_SIZE;
		      base_got = htab->elf.igotplt;
		    }

		  if (h->dynindx == -1
		      || h->forced_local
		      || info->symbolic)
		    {
		      /* This references the local defitionion.  We must
			 initialize this entry in the global offset table.
			 Since the offset must always be a multiple of 8,
			 we use the least significant bit to record
			 whether we have initialized it already.

			 When doing a dynamic link, we create a .rela.got
			 relocation entry to initialize the value.  This
			 is done in the finish_dynamic_symbol routine.	 */
		      if ((off & 1) != 0)
			off &= ~1;
		      else
			{
			  bfd_put_64 (output_bfd, relocation,
				      base_got->contents + off);
			  /* Note that this is harmless for the GOTPLT64
			     case, as -1 | 1 still is -1.  */
			  h->got.offset |= 1;
			}
		    }
		}

	      relocation = (base_got->output_section->vma
			    + base_got->output_offset + off);

	      goto do_relocation;
	    }

	  if (h->plt.offset == (bfd_vma) -1)
	    {
	      /* Handle static pointers of STT_GNU_IFUNC symbols.  */
	      if (r_type == htab->pointer_r_type
		  && (input_section->flags & SEC_CODE) == 0)
		goto do_ifunc_pointer;
	      goto bad_ifunc_reloc;
	    }

	  /* STT_GNU_IFUNC symbol must go through PLT.  */
	  if (htab->elf.splt != NULL)
	    {
	      if (htab->plt_second != NULL)
		{
		  resolved_plt = htab->plt_second;
		  plt_offset = eh->plt_second.offset;
		}
	      else
		{
		  resolved_plt = htab->elf.splt;
		  plt_offset =  h->plt.offset;
		}
	    }
	  else
	    {
	      resolved_plt = htab->elf.iplt;
	      plt_offset =  h->plt.offset;
	    }

	  relocation = (resolved_plt->output_section->vma
			+ resolved_plt->output_offset + plt_offset);

	  switch (r_type)
	    {
	    default:
	    bad_ifunc_reloc:
	      if (h->root.root.string)
		name = h->root.root.string;
	      else
		name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym,
					 NULL);
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("%pB: relocation %s against STT_GNU_IFUNC "
		   "symbol `%s' isn't supported"), input_bfd,
		 howto->name, name);
	      bfd_set_error (bfd_error_bad_value);
	      return false;

	    case R_X86_64_32S:
	      if (bfd_link_pic (info))
		abort ();
	      goto do_relocation;

	    case R_X86_64_32:
	      if (ABI_64_P (output_bfd))
		goto do_relocation;
	      /* FALLTHROUGH */
	    case R_X86_64_64:
	    do_ifunc_pointer:
	      if (rel->r_addend != 0)
		{
		  if (h->root.root.string)
		    name = h->root.root.string;
		  else
		    name = bfd_elf_sym_name (input_bfd, symtab_hdr,
					     sym, NULL);
		  _bfd_error_handler
		    /* xgettext:c-format */
		    (_("%pB: relocation %s against STT_GNU_IFUNC "
		       "symbol `%s' has non-zero addend: %" PRId64),
		     input_bfd, howto->name, name, (int64_t) rel->r_addend);
		  bfd_set_error (bfd_error_bad_value);
		  return false;
		}

	      /* Generate dynamic relcoation only when there is a
		 non-GOT reference in a shared object or there is no
		 PLT.  */
	      if ((bfd_link_pic (info) && h->non_got_ref)
		  || h->plt.offset == (bfd_vma) -1)
		{
		  Elf_Internal_Rela outrel;
		  asection *sreloc;

		  /* Need a dynamic relocation to get the real function
		     address.  */
		  outrel.r_offset = _bfd_elf_section_offset (output_bfd,
							     info,
							     input_section,
							     rel->r_offset);
		  if (outrel.r_offset == (bfd_vma) -1
		      || outrel.r_offset == (bfd_vma) -2)
		    abort ();

		  outrel.r_offset += (input_section->output_section->vma
				      + input_section->output_offset);

		  if (POINTER_LOCAL_IFUNC_P (info, h))
		    {
		      info->callbacks->minfo (_("Local IFUNC function `%s' in %pB\n"),
					      h->root.root.string,
					      h->root.u.def.section->owner);

		      /* This symbol is resolved locally.  */
		      outrel.r_info = htab->r_info (0, R_X86_64_IRELATIVE);
		      outrel.r_addend = (h->root.u.def.value
					 + h->root.u.def.section->output_section->vma
					 + h->root.u.def.section->output_offset);

		      if (htab->params->report_relative_reloc)
			_bfd_x86_elf_link_report_relative_reloc
			  (info, input_section, h, sym,
			   "R_X86_64_IRELATIVE", &outrel);
		    }
		  else
		    {
		      outrel.r_info = htab->r_info (h->dynindx, r_type);
		      outrel.r_addend = 0;
		    }

		  /* Dynamic relocations are stored in
		     1. .rela.ifunc section in PIC object.
		     2. .rela.got section in dynamic executable.
		     3. .rela.iplt section in static executable.  */
		  if (bfd_link_pic (info))
		    sreloc = htab->elf.irelifunc;
		  else if (htab->elf.splt != NULL)
		    sreloc = htab->elf.srelgot;
		  else
		    sreloc = htab->elf.irelplt;
		  elf_append_rela (output_bfd, sreloc, &outrel);

		  /* If this reloc is against an external symbol, we
		     do not want to fiddle with the addend.  Otherwise,
		     we need to include the symbol value so that it
		     becomes an addend for the dynamic reloc.  For an
		     internal symbol, we have updated addend.  */
		  continue;
		}
	      /* FALLTHROUGH */
	    case R_X86_64_PC32:
	    case R_X86_64_PC32_BND:
	    case R_X86_64_PC64:
	    case R_X86_64_PLT32:
	    case R_X86_64_PLT32_BND:
	      goto do_relocation;
	    }
	}

    skip_ifunc:
      resolved_to_zero = (eh != NULL
			  && UNDEFINED_WEAK_RESOLVED_TO_ZERO (info, eh));

      /* When generating a shared object, the relocations handled here are
	 copied into the output file to be resolved at run time.  */
      switch (r_type)
	{
	case R_X86_64_GOT32:
	case R_X86_64_GOT64:
	  /* Relocation is to the entry for this symbol in the global
	     offset table.  */
	case R_X86_64_GOTPCREL:
	case R_X86_64_GOTPCRELX:
	case R_X86_64_REX_GOTPCRELX:
	case R_X86_64_GOTPCREL64:
	  /* Use global offset table entry as symbol value.  */
	case R_X86_64_GOTPLT64:
	  /* This is obsolete and treated the same as GOT64.  */
	  base_got = htab->elf.sgot;

	  if (htab->elf.sgot == NULL)
	    abort ();

	  relative_reloc = false;
	  if (h != NULL)
	    {
	      off = h->got.offset;
	      if (h->needs_plt
		  && h->plt.offset != (bfd_vma)-1
		  && off == (bfd_vma)-1)
		{
		  /* We can't use h->got.offset here to save
		     state, or even just remember the offset, as
		     finish_dynamic_symbol would use that as offset into
		     .got.  */
		  bfd_vma plt_index = (h->plt.offset / plt_entry_size
				       - htab->plt.has_plt0);
		  off = (plt_index + 3) * GOT_ENTRY_SIZE;
		  base_got = htab->elf.sgotplt;
		}

	      if (RESOLVED_LOCALLY_P (info, h, htab))
		{
		  /* We must initialize this entry in the global offset
		     table.  Since the offset must always be a multiple
		     of 8, we use the least significant bit to record
		     whether we have initialized it already.

		     When doing a dynamic link, we create a .rela.got
		     relocation entry to initialize the value.	This is
		     done in the finish_dynamic_symbol routine.	 */
		  if ((off & 1) != 0)
		    off &= ~1;
		  else
		    {
		      bfd_put_64 (output_bfd, relocation,
				  base_got->contents + off);
		      /* Note that this is harmless for the GOTPLT64 case,
			 as -1 | 1 still is -1.  */
		      h->got.offset |= 1;

		      if (GENERATE_RELATIVE_RELOC_P (info, h))
			{
			  /* If this symbol isn't dynamic in PIC,
			     generate R_X86_64_RELATIVE here.  */
			  eh->no_finish_dynamic_symbol = 1;
			  relative_reloc = true;
			}
		    }
		}
	      else
		unresolved_reloc = false;
	    }
	  else
	    {
	      if (local_got_offsets == NULL)
		abort ();

	      off = local_got_offsets[r_symndx];

	      /* The offset must always be a multiple of 8.  We use
		 the least significant bit to record whether we have
		 already generated the necessary reloc.	 */
	      if ((off & 1) != 0)
		off &= ~1;
	      else
		{
		  bfd_put_64 (output_bfd, relocation,
			      base_got->contents + off);
		  local_got_offsets[r_symndx] |= 1;

		  /* NB: GOTPCREL relocations against local absolute
		     symbol store relocation value in the GOT slot
		     without relative relocation.  */
		  if (bfd_link_pic (info)
		      && !(sym->st_shndx == SHN_ABS
			   && (r_type == R_X86_64_GOTPCREL
			       || r_type == R_X86_64_GOTPCRELX
			       || r_type == R_X86_64_REX_GOTPCRELX)))
		    relative_reloc = true;
		}
	    }

	  if (relative_reloc)
	    {
	      asection *s;
	      Elf_Internal_Rela outrel;

	      /* We need to generate a R_X86_64_RELATIVE reloc
		 for the dynamic linker.  */
	      s = htab->elf.srelgot;
	      if (s == NULL)
		abort ();

	      outrel.r_offset = (base_got->output_section->vma
				 + base_got->output_offset
				 + off);
	      outrel.r_info = htab->r_info (0, R_X86_64_RELATIVE);
	      outrel.r_addend = relocation;

	      if (htab->params->report_relative_reloc)
		_bfd_x86_elf_link_report_relative_reloc
		  (info, input_section, h, sym, "R_X86_64_RELATIVE",
		   &outrel);

	      elf_append_rela (output_bfd, s, &outrel);
	    }

	  if (off >= (bfd_vma) -2)
	    abort ();

	  relocation = base_got->output_section->vma
		       + base_got->output_offset + off;
	  if (r_type != R_X86_64_GOTPCREL
	      && r_type != R_X86_64_GOTPCRELX
	      && r_type != R_X86_64_REX_GOTPCRELX
	      && r_type != R_X86_64_GOTPCREL64)
	    relocation -= htab->elf.sgotplt->output_section->vma
			  - htab->elf.sgotplt->output_offset;

	  break;

	case R_X86_64_GOTOFF64:
	  /* Relocation is relative to the start of the global offset
	     table.  */

	  /* Check to make sure it isn't a protected function or data
	     symbol for shared library since it may not be local when
	     used as function address or with copy relocation.  We also
	     need to make sure that a symbol is referenced locally.  */
	  if (bfd_link_pic (info) && h)
	    {
	      if (!h->def_regular)
		{
		  const char *v;

		  switch (ELF_ST_VISIBILITY (h->other))
		    {
		    case STV_HIDDEN:
		      v = _("hidden symbol");
		      break;
		    case STV_INTERNAL:
		      v = _("internal symbol");
		      break;
		    case STV_PROTECTED:
		      v = _("protected symbol");
		      break;
		    default:
		      v = _("symbol");
		      break;
		    }

		  _bfd_error_handler
		    /* xgettext:c-format */
		    (_("%pB: relocation R_X86_64_GOTOFF64 against undefined %s"
		       " `%s' can not be used when making a shared object"),
		     input_bfd, v, h->root.root.string);
		  bfd_set_error (bfd_error_bad_value);
		  return false;
		}
	      else if (!bfd_link_executable (info)
		       && !SYMBOL_REFERENCES_LOCAL_P (info, h)
		       && (h->type == STT_FUNC
			   || h->type == STT_OBJECT)
		       && ELF_ST_VISIBILITY (h->other) == STV_PROTECTED)
		{
		  _bfd_error_handler
		    /* xgettext:c-format */
		    (_("%pB: relocation R_X86_64_GOTOFF64 against protected %s"
		       " `%s' can not be used when making a shared object"),
		     input_bfd,
		     h->type == STT_FUNC ? "function" : "data",
		     h->root.root.string);
		  bfd_set_error (bfd_error_bad_value);
		  return false;
		}
	    }

	  /* Note that sgot is not involved in this
	     calculation.  We always want the start of .got.plt.  If we
	     defined _GLOBAL_OFFSET_TABLE_ in a different way, as is
	     permitted by the ABI, we might have to change this
	     calculation.  */
	  relocation -= htab->elf.sgotplt->output_section->vma
			+ htab->elf.sgotplt->output_offset;
	  break;

	case R_X86_64_GOTPC32:
	case R_X86_64_GOTPC64:
	  /* Use global offset table as symbol value.  */
	  relocation = htab->elf.sgotplt->output_section->vma
		       + htab->elf.sgotplt->output_offset;
	  unresolved_reloc = false;
	  break;

	case R_X86_64_PLTOFF64:
	  /* Relocation is PLT entry relative to GOT.  For local
	     symbols it's the symbol itself relative to GOT.  */
	  if (h != NULL
	      /* See PLT32 handling.  */
	      && (h->plt.offset != (bfd_vma) -1
		  || eh->plt_got.offset != (bfd_vma) -1)
	      && htab->elf.splt != NULL)
	    {
	      if (eh->plt_got.offset != (bfd_vma) -1)
		{
		  /* Use the GOT PLT.  */
		  resolved_plt = htab->plt_got;
		  plt_offset = eh->plt_got.offset;
		}
	      else if (htab->plt_second != NULL)
		{
		  resolved_plt = htab->plt_second;
		  plt_offset = eh->plt_second.offset;
		}
	      else
		{
		  resolved_plt = htab->elf.splt;
		  plt_offset = h->plt.offset;
		}

	      relocation = (resolved_plt->output_section->vma
			    + resolved_plt->output_offset
			    + plt_offset);
	      unresolved_reloc = false;
	    }

	  relocation -= htab->elf.sgotplt->output_section->vma
			+ htab->elf.sgotplt->output_offset;
	  break;

	case R_X86_64_PLT32:
	case R_X86_64_PLT32_BND:
	  /* Relocation is to the entry for this symbol in the
	     procedure linkage table.  */

	  /* Resolve a PLT32 reloc against a local symbol directly,
	     without using the procedure linkage table.	 */
	  if (h == NULL)
	    break;

	  if ((h->plt.offset == (bfd_vma) -1
	       && eh->plt_got.offset == (bfd_vma) -1)
	      || htab->elf.splt == NULL)
	    {
	      /* We didn't make a PLT entry for this symbol.  This
		 happens when statically linking PIC code, or when
		 using -Bsymbolic.  */
	      break;
	    }

	use_plt:
	  if (h->plt.offset != (bfd_vma) -1)
	    {
	      if (htab->plt_second != NULL)
		{
		  resolved_plt = htab->plt_second;
		  plt_offset = eh->plt_second.offset;
		}
	      else
		{
		  resolved_plt = htab->elf.splt;
		  plt_offset = h->plt.offset;
		}
	    }
	  else
	    {
	      /* Use the GOT PLT.  */
	      resolved_plt = htab->plt_got;
	      plt_offset = eh->plt_got.offset;
	    }

	  relocation = (resolved_plt->output_section->vma
			+ resolved_plt->output_offset
			+ plt_offset);
	  unresolved_reloc = false;
	  break;

	case R_X86_64_SIZE32:
	case R_X86_64_SIZE64:
	  /* Set to symbol size.  */
	  relocation = st_size;
	  goto direct;

	case R_X86_64_PC8:
	case R_X86_64_PC16:
	case R_X86_64_PC32:
	case R_X86_64_PC32_BND:
	  /* Don't complain about -fPIC if the symbol is undefined when
	     building executable unless it is unresolved weak symbol,
	     references a dynamic definition in PIE or -z nocopyreloc
	     is used.  */
	  no_copyreloc_p
	    = (info->nocopyreloc
	       || (h != NULL
		   && !h->root.linker_def
		   && !h->root.ldscript_def
		   && eh->def_protected
		   && elf_has_no_copy_on_protected (h->root.u.def.section->owner)));

	  if ((input_section->flags & SEC_ALLOC) != 0
	      && (input_section->flags & SEC_READONLY) != 0
	      && h != NULL
	      && ((bfd_link_executable (info)
		   && ((h->root.type == bfd_link_hash_undefweak
			&& (eh == NULL
			    || !UNDEFINED_WEAK_RESOLVED_TO_ZERO (info,
								 eh)))
		       || (bfd_link_pie (info)
			   && !SYMBOL_DEFINED_NON_SHARED_P (h)
			   && h->def_dynamic)
		       || (no_copyreloc_p
			   && h->def_dynamic
			   && !(h->root.u.def.section->flags & SEC_CODE))))
		  || bfd_link_dll (info)))
	    {
	      bool fail = false;
	      if (SYMBOL_REFERENCES_LOCAL_P (info, h))
		{
		  /* Symbol is referenced locally.  Make sure it is
		     defined locally.  */
		  fail = !SYMBOL_DEFINED_NON_SHARED_P (h);
		}
	      else if (bfd_link_pie (info))
		{
		  /* We can only use PC-relative relocations in PIE
		     from non-code sections.  */
		  if (h->type == STT_FUNC
		      && (sec->flags & SEC_CODE) != 0)
		    fail = true;
		}
	      else if (no_copyreloc_p || bfd_link_dll (info))
		{
		  /* Symbol doesn't need copy reloc and isn't
		     referenced locally.  Don't allow PC-relative
		     relocations against default and protected
		     symbols since address of protected function
		     and location of protected data may not be in
		     the shared object.   */
		  fail = (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
			  || ELF_ST_VISIBILITY (h->other) == STV_PROTECTED);
		}

	      if (fail)
		return elf_x86_64_need_pic (info, input_bfd, input_section,
					    h, NULL, NULL, howto);
	    }
	  /* Since x86-64 has PC-relative PLT, we can use PLT in PIE
	     as function address.  */
	  else if (h != NULL
		   && (input_section->flags & SEC_CODE) == 0
		   && bfd_link_pie (info)
		   && h->type == STT_FUNC
		   && !h->def_regular
		   && h->def_dynamic)
	    goto use_plt;
	  /* Fall through.  */

	case R_X86_64_8:
	case R_X86_64_16:
	case R_X86_64_32:
	case R_X86_64_PC64:
	case R_X86_64_64:
	  /* FIXME: The ABI says the linker should make sure the value is
	     the same when it's zeroextended to 64 bit.	 */

	direct:
	  if ((input_section->flags & SEC_ALLOC) == 0)
	    break;

	  need_copy_reloc_in_pie = (bfd_link_pie (info)
				    && h != NULL
				    && (h->needs_copy
					|| eh->needs_copy
					|| (h->root.type
					    == bfd_link_hash_undefined))
				    && (X86_PCREL_TYPE_P (r_type)
					|| X86_SIZE_TYPE_P (r_type)));

	  if (GENERATE_DYNAMIC_RELOCATION_P (info, eh, r_type, sec,
					     need_copy_reloc_in_pie,
					     resolved_to_zero, false))
	    {
	      Elf_Internal_Rela outrel;
	      bool skip, relocate;
	      asection *sreloc;
	      const char *relative_reloc_name = NULL;

	      /* When generating a shared object, these relocations
		 are copied into the output file to be resolved at run
		 time.	*/
	      skip = false;
	      relocate = false;

	      outrel.r_offset =
		_bfd_elf_section_offset (output_bfd, info, input_section,
					 rel->r_offset);
	      if (outrel.r_offset == (bfd_vma) -1)
		skip = true;
	      else if (outrel.r_offset == (bfd_vma) -2)
		skip = true, relocate = true;

	      outrel.r_offset += (input_section->output_section->vma
				  + input_section->output_offset);

	      if (skip)
		memset (&outrel, 0, sizeof outrel);

	      else if (COPY_INPUT_RELOC_P (info, h, r_type))
		{
		  outrel.r_info = htab->r_info (h->dynindx, r_type);
		  outrel.r_addend = rel->r_addend;
		}
	      else
		{
		  /* This symbol is local, or marked to become local.
		     When relocation overflow check is disabled, we
		     convert R_X86_64_32 to dynamic R_X86_64_RELATIVE.  */
		  if (r_type == htab->pointer_r_type
		      || (r_type == R_X86_64_32
			  && htab->params->no_reloc_overflow_check))
		    {
		      relocate = true;
		      outrel.r_info = htab->r_info (0, R_X86_64_RELATIVE);
		      outrel.r_addend = relocation + rel->r_addend;
		      relative_reloc_name = "R_X86_64_RELATIVE";
		    }
		  else if (r_type == R_X86_64_64
			   && !ABI_64_P (output_bfd))
		    {
		      relocate = true;
		      outrel.r_info = htab->r_info (0,
						    R_X86_64_RELATIVE64);
		      outrel.r_addend = relocation + rel->r_addend;
		      relative_reloc_name = "R_X86_64_RELATIVE64";
		      /* Check addend overflow.  */
		      if ((outrel.r_addend & 0x80000000)
			  != (rel->r_addend & 0x80000000))
			{
			  const char *name;
			  int addend = rel->r_addend;
			  if (h && h->root.root.string)
			    name = h->root.root.string;
			  else
			    name = bfd_elf_sym_name (input_bfd, symtab_hdr,
						     sym, NULL);
			  _bfd_error_handler
			    /* xgettext:c-format */
			    (_("%pB: addend %s%#x in relocation %s against "
			       "symbol `%s' at %#" PRIx64
			       " in section `%pA' is out of range"),
			     input_bfd, addend < 0 ? "-" : "", addend,
			     howto->name, name, (uint64_t) rel->r_offset,
			     input_section);
			  bfd_set_error (bfd_error_bad_value);
			  return false;
			}
		    }
		  else
		    {
		      long sindx;

		      if (bfd_is_abs_section (sec))
			sindx = 0;
		      else if (sec == NULL || sec->owner == NULL)
			{
			  bfd_set_error (bfd_error_bad_value);
			  return false;
			}
		      else
			{
			  asection *osec;

			  /* We are turning this relocation into one
			     against a section symbol.  It would be
			     proper to subtract the symbol's value,
			     osec->vma, from the emitted reloc addend,
			     but ld.so expects buggy relocs.  */
			  osec = sec->output_section;
			  sindx = elf_section_data (osec)->dynindx;
			  if (sindx == 0)
			    {
			      asection *oi = htab->elf.text_index_section;
			      sindx = elf_section_data (oi)->dynindx;
			    }
			  BFD_ASSERT (sindx != 0);
			}

		      outrel.r_info = htab->r_info (sindx, r_type);
		      outrel.r_addend = relocation + rel->r_addend;
		    }
		}

	      sreloc = elf_section_data (input_section)->sreloc;

	      if (sreloc == NULL || sreloc->contents == NULL)
		{
		  r = bfd_reloc_notsupported;
		  goto check_relocation_error;
		}

	      if (relative_reloc_name
		  && htab->params->report_relative_reloc)
		_bfd_x86_elf_link_report_relative_reloc
		  (info, input_section, h, sym, relative_reloc_name,
		   &outrel);

	      elf_append_rela (output_bfd, sreloc, &outrel);

	      /* If this reloc is against an external symbol, we do
		 not want to fiddle with the addend.  Otherwise, we
		 need to include the symbol value so that it becomes
		 an addend for the dynamic reloc.  */
	      if (! relocate)
		continue;
	    }

	  break;

	case R_X86_64_TLSGD:
	case R_X86_64_GOTPC32_TLSDESC:
	case R_X86_64_TLSDESC_CALL:
	case R_X86_64_GOTTPOFF:
	  tls_type = GOT_UNKNOWN;
	  if (h == NULL && local_got_offsets)
	    tls_type = elf_x86_local_got_tls_type (input_bfd) [r_symndx];
	  else if (h != NULL)
	    tls_type = elf_x86_hash_entry (h)->tls_type;

	  r_type_tls = r_type;
	  if (! elf_x86_64_tls_transition (info, input_bfd,
					   input_section, contents,
					   symtab_hdr, sym_hashes,
					   &r_type_tls, tls_type, rel,
					   relend, h, r_symndx, true))
	    return false;

	  if (r_type_tls == R_X86_64_TPOFF32)
	    {
	      bfd_vma roff = rel->r_offset;

	      BFD_ASSERT (! unresolved_reloc);

	      if (r_type == R_X86_64_TLSGD)
		{
		  /* GD->LE transition.  For 64bit, change
			.byte 0x66; leaq foo@tlsgd(%rip), %rdi
			.word 0x6666; rex64; call __tls_get_addr@PLT
		     or
			.byte 0x66; leaq foo@tlsgd(%rip), %rdi
			.byte 0x66; rex64
			call *__tls_get_addr@GOTPCREL(%rip)
			which may be converted to
			addr32 call __tls_get_addr
		     into:
			movq %fs:0, %rax
			leaq foo@tpoff(%rax), %rax
		     For 32bit, change
			leaq foo@tlsgd(%rip), %rdi
			.word 0x6666; rex64; call __tls_get_addr@PLT
		     or
			leaq foo@tlsgd(%rip), %rdi
			.byte 0x66; rex64
			call *__tls_get_addr@GOTPCREL(%rip)
			which may be converted to
			addr32 call __tls_get_addr
		     into:
			movl %fs:0, %eax
			leaq foo@tpoff(%rax), %rax
		     For largepic, change:
			leaq foo@tlsgd(%rip), %rdi
			movabsq $__tls_get_addr@pltoff, %rax
			addq %r15, %rax
			call *%rax
		     into:
			movq %fs:0, %rax
			leaq foo@tpoff(%rax), %rax
			nopw 0x0(%rax,%rax,1)  */
		  int largepic = 0;
		  if (ABI_64_P (output_bfd))
		    {
		      if (contents[roff + 5] == 0xb8)
			{
			  if (roff < 3
			      || (roff - 3 + 22) > input_section->size)
			    {
			    corrupt_input:
			      info->callbacks->einfo
				(_("%F%P: corrupt input: %pB\n"),
				 input_bfd);
			      return false;
			    }
			  memcpy (contents + roff - 3,
				  "\x64\x48\x8b\x04\x25\0\0\0\0\x48\x8d\x80"
				  "\0\0\0\0\x66\x0f\x1f\x44\0", 22);
			  largepic = 1;
			}
		      else
			{
			  if (roff < 4
			      || (roff - 4 + 16) > input_section->size)
			    goto corrupt_input;
			  memcpy (contents + roff - 4,
				  "\x64\x48\x8b\x04\x25\0\0\0\0\x48\x8d\x80\0\0\0",
				  16);
			}
		    }
		  else
		    {
		      if (roff < 3
			  || (roff - 3 + 15) > input_section->size)
			goto corrupt_input;
		      memcpy (contents + roff - 3,
			      "\x64\x8b\x04\x25\0\0\0\0\x48\x8d\x80\0\0\0",
			      15);
		    }
		  bfd_put_32 (output_bfd,
			      elf_x86_64_tpoff (info, relocation),
			      contents + roff + 8 + largepic);
		  /* Skip R_X86_64_PC32, R_X86_64_PLT32,
		     R_X86_64_GOTPCRELX and R_X86_64_PLTOFF64.  */
		  rel++;
		  wrel++;
		  continue;
		}
	      else if (r_type == R_X86_64_GOTPC32_TLSDESC)
		{
		  /* GDesc -> LE transition.
		     It's originally something like:
		     leaq x@tlsdesc(%rip), %rax <--- LP64 mode.
		     rex leal x@tlsdesc(%rip), %eax <--- X32 mode.

		     Change it to:
		     movq $x@tpoff, %rax <--- LP64 mode.
		     rex movl $x@tpoff, %eax <--- X32 mode.
		   */

		  unsigned int val, type;

		  if (roff < 3)
		    goto corrupt_input;
		  type = bfd_get_8 (input_bfd, contents + roff - 3);
		  val = bfd_get_8 (input_bfd, contents + roff - 1);
		  bfd_put_8 (output_bfd,
			     (type & 0x48) | ((type >> 2) & 1),
			     contents + roff - 3);
		  bfd_put_8 (output_bfd, 0xc7, contents + roff - 2);
		  bfd_put_8 (output_bfd, 0xc0 | ((val >> 3) & 7),
			     contents + roff - 1);
		  bfd_put_32 (output_bfd,
			      elf_x86_64_tpoff (info, relocation),
			      contents + roff);
		  continue;
		}
	      else if (r_type == R_X86_64_TLSDESC_CALL)
		{
		  /* GDesc -> LE transition.
		     It's originally:
		     call *(%rax) <--- LP64 mode.
		     call *(%eax) <--- X32 mode.
		     Turn it into:
		     xchg %ax,%ax <-- LP64 mode.
		     nopl (%rax)  <-- X32 mode.
		   */
		  unsigned int prefix = 0;
		  if (!ABI_64_P (input_bfd))
		    {
		      /* Check for call *x@tlsdesc(%eax).  */
		      if (contents[roff] == 0x67)
			prefix = 1;
		    }
		  if (prefix)
		    {
		      bfd_put_8 (output_bfd, 0x0f, contents + roff);
		      bfd_put_8 (output_bfd, 0x1f, contents + roff + 1);
		      bfd_put_8 (output_bfd, 0x00, contents + roff + 2);
		    }
		  else
		    {
		      bfd_put_8 (output_bfd, 0x66, contents + roff);
		      bfd_put_8 (output_bfd, 0x90, contents + roff + 1);
		    }
		  continue;
		}
	      else if (r_type == R_X86_64_GOTTPOFF)
		{
		  /* IE->LE transition:
		     For 64bit, originally it can be one of:
		     movq foo@gottpoff(%rip), %reg
		     addq foo@gottpoff(%rip), %reg
		     We change it into:
		     movq $foo, %reg
		     leaq foo(%reg), %reg
		     addq $foo, %reg.
		     For 32bit, originally it can be one of:
		     movq foo@gottpoff(%rip), %reg
		     addl foo@gottpoff(%rip), %reg
		     We change it into:
		     movq $foo, %reg
		     leal foo(%reg), %reg
		     addl $foo, %reg. */

		  unsigned int val, type, reg;

		  if (roff >= 3)
		    val = bfd_get_8 (input_bfd, contents + roff - 3);
		  else
		    {
		      if (roff < 2)
			goto corrupt_input;
		      val = 0;
		    }
		  type = bfd_get_8 (input_bfd, contents + roff - 2);
		  reg = bfd_get_8 (input_bfd, contents + roff - 1);
		  reg >>= 3;
		  if (type == 0x8b)
		    {
		      /* movq */
		      if (val == 0x4c)
			{
			  if (roff < 3)
			    goto corrupt_input;
			  bfd_put_8 (output_bfd, 0x49,
				     contents + roff - 3);
			}
		      else if (!ABI_64_P (output_bfd) && val == 0x44)
			{
			  if (roff < 3)
			    goto corrupt_input;
			  bfd_put_8 (output_bfd, 0x41,
				     contents + roff - 3);
			}
		      bfd_put_8 (output_bfd, 0xc7,
				 contents + roff - 2);
		      bfd_put_8 (output_bfd, 0xc0 | reg,
				 contents + roff - 1);
		    }
		  else if (reg == 4)
		    {
		      /* addq/addl -> addq/addl - addressing with %rsp/%r12
			 is special  */
		      if (val == 0x4c)
			{
			  if (roff < 3)
			    goto corrupt_input;
			  bfd_put_8 (output_bfd, 0x49,
				     contents + roff - 3);
			}
		      else if (!ABI_64_P (output_bfd) && val == 0x44)
			{
			  if (roff < 3)
			    goto corrupt_input;
			  bfd_put_8 (output_bfd, 0x41,
				     contents + roff - 3);
			}
		      bfd_put_8 (output_bfd, 0x81,
				 contents + roff - 2);
		      bfd_put_8 (output_bfd, 0xc0 | reg,
				 contents + roff - 1);
		    }
		  else
		    {
		      /* addq/addl -> leaq/leal */
		      if (val == 0x4c)
			{
			  if (roff < 3)
			    goto corrupt_input;
			  bfd_put_8 (output_bfd, 0x4d,
				     contents + roff - 3);
			}
		      else if (!ABI_64_P (output_bfd) && val == 0x44)
			{
			  if (roff < 3)
			    goto corrupt_input;
			  bfd_put_8 (output_bfd, 0x45,
				     contents + roff - 3);
			}
		      bfd_put_8 (output_bfd, 0x8d,
				 contents + roff - 2);
		      bfd_put_8 (output_bfd, 0x80 | reg | (reg << 3),
				 contents + roff - 1);
		    }
		  bfd_put_32 (output_bfd,
			      elf_x86_64_tpoff (info, relocation),
			      contents + roff);
		  continue;
		}
	      else
		BFD_ASSERT (false);
	    }

	  if (htab->elf.sgot == NULL)
	    abort ();

	  if (h != NULL)
	    {
	      off = h->got.offset;
	      offplt = elf_x86_hash_entry (h)->tlsdesc_got;
	    }
	  else
	    {
	      if (local_got_offsets == NULL)
		abort ();

	      off = local_got_offsets[r_symndx];
	      offplt = local_tlsdesc_gotents[r_symndx];
	    }

	  if ((off & 1) != 0)
	    off &= ~1;
	  else
	    {
	      Elf_Internal_Rela outrel;
	      int dr_type, indx;
	      asection *sreloc;

	      if (htab->elf.srelgot == NULL)
		abort ();

	      indx = h && h->dynindx != -1 ? h->dynindx : 0;

	      if (GOT_TLS_GDESC_P (tls_type))
		{
		  outrel.r_info = htab->r_info (indx, R_X86_64_TLSDESC);
		  BFD_ASSERT (htab->sgotplt_jump_table_size + offplt
			      + 2 * GOT_ENTRY_SIZE <= htab->elf.sgotplt->size);
		  outrel.r_offset = (htab->elf.sgotplt->output_section->vma
				     + htab->elf.sgotplt->output_offset
				     + offplt
				     + htab->sgotplt_jump_table_size);
		  sreloc = htab->elf.srelplt;
		  if (indx == 0)
		    outrel.r_addend = relocation - _bfd_x86_elf_dtpoff_base (info);
		  else
		    outrel.r_addend = 0;
		  elf_append_rela (output_bfd, sreloc, &outrel);
		}

	      sreloc = htab->elf.srelgot;

	      outrel.r_offset = (htab->elf.sgot->output_section->vma
				 + htab->elf.sgot->output_offset + off);

	      if (GOT_TLS_GD_P (tls_type))
		dr_type = R_X86_64_DTPMOD64;
	      else if (GOT_TLS_GDESC_P (tls_type))
		goto dr_done;
	      else
		dr_type = R_X86_64_TPOFF64;

	      bfd_put_64 (output_bfd, 0, htab->elf.sgot->contents + off);
	      outrel.r_addend = 0;
	      if ((dr_type == R_X86_64_TPOFF64
		   || dr_type == R_X86_64_TLSDESC) && indx == 0)
		outrel.r_addend = relocation - _bfd_x86_elf_dtpoff_base (info);
	      outrel.r_info = htab->r_info (indx, dr_type);

	      elf_append_rela (output_bfd, sreloc, &outrel);

	      if (GOT_TLS_GD_P (tls_type))
		{
		  if (indx == 0)
		    {
		      BFD_ASSERT (! unresolved_reloc);
		      bfd_put_64 (output_bfd,
				  relocation - _bfd_x86_elf_dtpoff_base (info),
				  htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
		    }
		  else
		    {
		      bfd_put_64 (output_bfd, 0,
				  htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
		      outrel.r_info = htab->r_info (indx,
						    R_X86_64_DTPOFF64);
		      outrel.r_offset += GOT_ENTRY_SIZE;
		      elf_append_rela (output_bfd, sreloc,
						&outrel);
		    }
		}

	    dr_done:
	      if (h != NULL)
		h->got.offset |= 1;
	      else
		local_got_offsets[r_symndx] |= 1;
	    }

	  if (off >= (bfd_vma) -2
	      && ! GOT_TLS_GDESC_P (tls_type))
	    abort ();
	  if (r_type_tls == r_type)
	    {
	      if (r_type == R_X86_64_GOTPC32_TLSDESC
		  || r_type == R_X86_64_TLSDESC_CALL)
		relocation = htab->elf.sgotplt->output_section->vma
		  + htab->elf.sgotplt->output_offset
		  + offplt + htab->sgotplt_jump_table_size;
	      else
		relocation = htab->elf.sgot->output_section->vma
		  + htab->elf.sgot->output_offset + off;
	      unresolved_reloc = false;
	    }
	  else
	    {
	      bfd_vma roff = rel->r_offset;

	      if (r_type == R_X86_64_TLSGD)
		{
		  /* GD->IE transition.  For 64bit, change
			.byte 0x66; leaq foo@tlsgd(%rip), %rdi
			.word 0x6666; rex64; call __tls_get_addr@PLT
		     or
			.byte 0x66; leaq foo@tlsgd(%rip), %rdi
			.byte 0x66; rex64
			call *__tls_get_addr@GOTPCREL(%rip
			which may be converted to
			addr32 call __tls_get_addr
		     into:
			movq %fs:0, %rax
			addq foo@gottpoff(%rip), %rax
		     For 32bit, change
			leaq foo@tlsgd(%rip), %rdi
			.word 0x6666; rex64; call __tls_get_addr@PLT
		     or
			leaq foo@tlsgd(%rip), %rdi
			.byte 0x66; rex64;
			call *__tls_get_addr@GOTPCREL(%rip)
			which may be converted to
			addr32 call __tls_get_addr
		     into:
			movl %fs:0, %eax
			addq foo@gottpoff(%rip), %rax
		     For largepic, change:
			leaq foo@tlsgd(%rip), %rdi
			movabsq $__tls_get_addr@pltoff, %rax
			addq %r15, %rax
			call *%rax
		     into:
			movq %fs:0, %rax
			addq foo@gottpoff(%rax), %rax
			nopw 0x0(%rax,%rax,1)  */
		  int largepic = 0;
		  if (ABI_64_P (output_bfd))
		    {
		      if (contents[roff + 5] == 0xb8)
			{
			  if (roff < 3
			      || (roff - 3 + 22) > input_section->size)
			    goto corrupt_input;
			  memcpy (contents + roff - 3,
				  "\x64\x48\x8b\x04\x25\0\0\0\0\x48\x03\x05"
				  "\0\0\0\0\x66\x0f\x1f\x44\0", 22);
			  largepic = 1;
			}
		      else
			{
			  if (roff < 4
			      || (roff - 4 + 16) > input_section->size)
			    goto corrupt_input;
			  memcpy (contents + roff - 4,
				  "\x64\x48\x8b\x04\x25\0\0\0\0\x48\x03\x05\0\0\0",
				  16);
			}
		    }
		  else
		    {
		      if (roff < 3
			  || (roff - 3 + 15) > input_section->size)
			goto corrupt_input;
		      memcpy (contents + roff - 3,
			      "\x64\x8b\x04\x25\0\0\0\0\x48\x03\x05\0\0\0",
			      15);
		    }

		  relocation = (htab->elf.sgot->output_section->vma
				+ htab->elf.sgot->output_offset + off
				- roff
				- largepic
				- input_section->output_section->vma
				- input_section->output_offset
				- 12);
		  bfd_put_32 (output_bfd, relocation,
			      contents + roff + 8 + largepic);
		  /* Skip R_X86_64_PLT32/R_X86_64_PLTOFF64.  */
		  rel++;
		  wrel++;
		  continue;
		}
	      else if (r_type == R_X86_64_GOTPC32_TLSDESC)
		{
		  /* GDesc -> IE transition.
		     It's originally something like:
		     leaq x@tlsdesc(%rip), %rax <--- LP64 mode.
		     rex leal x@tlsdesc(%rip), %eax <--- X32 mode.

		     Change it to:
		     # before xchg %ax,%ax in LP64 mode.
		     movq x@gottpoff(%rip), %rax
		     # before nopl (%rax) in X32 mode.
		     rex movl x@gottpoff(%rip), %eax
		  */

		  /* Now modify the instruction as appropriate. To
		     turn a lea into a mov in the form we use it, it
		     suffices to change the second byte from 0x8d to
		     0x8b.  */
		  if (roff < 2)
		    goto corrupt_input;
		  bfd_put_8 (output_bfd, 0x8b, contents + roff - 2);

		  bfd_put_32 (output_bfd,
			      htab->elf.sgot->output_section->vma
			      + htab->elf.sgot->output_offset + off
			      - rel->r_offset
			      - input_section->output_section->vma
			      - input_section->output_offset
			      - 4,
			      contents + roff);
		  continue;
		}
	      else if (r_type == R_X86_64_TLSDESC_CALL)
		{
		  /* GDesc -> IE transition.
		     It's originally:
		     call *(%rax) <--- LP64 mode.
		     call *(%eax) <--- X32 mode.

		     Change it to:
		     xchg %ax, %ax <-- LP64 mode.
		     nopl (%rax)  <-- X32 mode.
		   */

		  unsigned int prefix = 0;
		  if (!ABI_64_P (input_bfd))
		    {
		      /* Check for call *x@tlsdesc(%eax).  */
		      if (contents[roff] == 0x67)
			prefix = 1;
		    }
		  if (prefix)
		    {
		      bfd_put_8 (output_bfd, 0x0f, contents + roff);
		      bfd_put_8 (output_bfd, 0x1f, contents + roff + 1);
		      bfd_put_8 (output_bfd, 0x00, contents + roff + 2);
		    }
		  else
		    {
		      bfd_put_8 (output_bfd, 0x66, contents + roff);
		      bfd_put_8 (output_bfd, 0x90, contents + roff + 1);
		    }
		  continue;
		}
	      else
		BFD_ASSERT (false);
	    }
	  break;

	case R_X86_64_TLSLD:
	  if (! elf_x86_64_tls_transition (info, input_bfd,
					   input_section, contents,
					   symtab_hdr, sym_hashes,
					   &r_type, GOT_UNKNOWN, rel,
					   relend, h, r_symndx, true))
	    return false;

	  if (r_type != R_X86_64_TLSLD)
	    {
	      /* LD->LE transition:
			leaq foo@tlsld(%rip), %rdi
			call __tls_get_addr@PLT
		 For 64bit, we change it into:
			.word 0x6666; .byte 0x66; movq %fs:0, %rax
		 For 32bit, we change it into:
			nopl 0x0(%rax); movl %fs:0, %eax
		 Or
			leaq foo@tlsld(%rip), %rdi;
			call *__tls_get_addr@GOTPCREL(%rip)
			which may be converted to
			addr32 call __tls_get_addr
		 For 64bit, we change it into:
			.word 0x6666; .word 0x6666; movq %fs:0, %rax
		 For 32bit, we change it into:
			nopw 0x0(%rax); movl %fs:0, %eax
		 For largepic, change:
			leaq foo@tlsgd(%rip), %rdi
			movabsq $__tls_get_addr@pltoff, %rax
			addq %rbx, %rax
			call *%rax
		 into
			data16 data16 data16 nopw %cs:0x0(%rax,%rax,1)
			movq %fs:0, %eax  */

	      BFD_ASSERT (r_type == R_X86_64_TPOFF32);
	      if (ABI_64_P (output_bfd))
		{
		  if ((rel->r_offset + 5) >= input_section->size)
		    goto corrupt_input;
		  if (contents[rel->r_offset + 5] == 0xb8)
		    {
		      if (rel->r_offset < 3
			  || (rel->r_offset - 3 + 22) > input_section->size)
			goto corrupt_input;
		      memcpy (contents + rel->r_offset - 3,
			      "\x66\x66\x66\x66\x2e\x0f\x1f\x84\0\0\0\0\0"
			      "\x64\x48\x8b\x04\x25\0\0\0", 22);
		    }
		  else if (contents[rel->r_offset + 4] == 0xff
			   || contents[rel->r_offset + 4] == 0x67)
		    {
		      if (rel->r_offset < 3
			  || (rel->r_offset - 3 + 13) > input_section->size)
			goto corrupt_input;
		      memcpy (contents + rel->r_offset - 3,
			      "\x66\x66\x66\x66\x64\x48\x8b\x04\x25\0\0\0",
			      13);

		    }
		  else
		    {
		      if (rel->r_offset < 3
			  || (rel->r_offset - 3 + 12) > input_section->size)
			goto corrupt_input;
		      memcpy (contents + rel->r_offset - 3,
			      "\x66\x66\x66\x64\x48\x8b\x04\x25\0\0\0", 12);
		    }
		}
	      else
		{
		  if ((rel->r_offset + 4) >= input_section->size)
		    goto corrupt_input;
		  if (contents[rel->r_offset + 4] == 0xff)
		    {
		      if (rel->r_offset < 3
			  || (rel->r_offset - 3 + 13) > input_section->size)
			goto corrupt_input;
		      memcpy (contents + rel->r_offset - 3,
			      "\x66\x0f\x1f\x40\x00\x64\x8b\x04\x25\0\0\0",
			      13);
		    }
		  else
		    {
		      if (rel->r_offset < 3
			  || (rel->r_offset - 3 + 12) > input_section->size)
			goto corrupt_input;
		      memcpy (contents + rel->r_offset - 3,
			      "\x0f\x1f\x40\x00\x64\x8b\x04\x25\0\0\0", 12);
		    }
		}
	      /* Skip R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_GOTPCRELX
		 and R_X86_64_PLTOFF64.  */
	      rel++;
	      wrel++;
	      continue;
	    }

	  if (htab->elf.sgot == NULL)
	    abort ();

	  off = htab->tls_ld_or_ldm_got.offset;
	  if (off & 1)
	    off &= ~1;
	  else
	    {
	      Elf_Internal_Rela outrel;

	      if (htab->elf.srelgot == NULL)
		abort ();

	      outrel.r_offset = (htab->elf.sgot->output_section->vma
				 + htab->elf.sgot->output_offset + off);

	      bfd_put_64 (output_bfd, 0,
			  htab->elf.sgot->contents + off);
	      bfd_put_64 (output_bfd, 0,
			  htab->elf.sgot->contents + off + GOT_ENTRY_SIZE);
	      outrel.r_info = htab->r_info (0, R_X86_64_DTPMOD64);
	      outrel.r_addend = 0;
	      elf_append_rela (output_bfd, htab->elf.srelgot,
					&outrel);
	      htab->tls_ld_or_ldm_got.offset |= 1;
	    }
	  relocation = htab->elf.sgot->output_section->vma
		       + htab->elf.sgot->output_offset + off;
	  unresolved_reloc = false;
	  break;

	case R_X86_64_DTPOFF32:
	  if (!bfd_link_executable (info)
	      || (input_section->flags & SEC_CODE) == 0)
	    relocation -= _bfd_x86_elf_dtpoff_base (info);
	  else
	    relocation = elf_x86_64_tpoff (info, relocation);
	  break;

	case R_X86_64_TPOFF32:
	case R_X86_64_TPOFF64:
	  BFD_ASSERT (bfd_link_executable (info));
	  relocation = elf_x86_64_tpoff (info, relocation);
	  break;

	case R_X86_64_DTPOFF64:
	  BFD_ASSERT ((input_section->flags & SEC_CODE) == 0);
	  relocation -= _bfd_x86_elf_dtpoff_base (info);
	  break;

	default:
	  break;
	}

      /* Dynamic relocs are not propagated for SEC_DEBUGGING sections
	 because such sections are not SEC_ALLOC and thus ld.so will
	 not process them.  */
      if (unresolved_reloc
	  && !((input_section->flags & SEC_DEBUGGING) != 0
	       && h->def_dynamic)
	  && _bfd_elf_section_offset (output_bfd, info, input_section,
				      rel->r_offset) != (bfd_vma) -1)
	{
	  switch (r_type)
	    {
	    case R_X86_64_32S:
	      sec = h->root.u.def.section;
	      if ((info->nocopyreloc
		   || (eh->def_protected
		       && elf_has_no_copy_on_protected (h->root.u.def.section->owner)))
		  && !(h->root.u.def.section->flags & SEC_CODE))
		return elf_x86_64_need_pic (info, input_bfd, input_section,
					    h, NULL, NULL, howto);
	      /* Fall through.  */

	    default:
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("%pB(%pA+%#" PRIx64 "): "
		   "unresolvable %s relocation against symbol `%s'"),
		 input_bfd,
		 input_section,
		 (uint64_t) rel->r_offset,
		 howto->name,
		 h->root.root.string);
	      return false;
	    }
	}

    do_relocation:
      r = _bfd_final_link_relocate (howto, input_bfd, input_section,
				    contents, rel->r_offset,
				    relocation, rel->r_addend);

    check_relocation_error:
      if (r != bfd_reloc_ok)
	{
	  const char *name;

	  if (h != NULL)
	    name = h->root.root.string;
	  else
	    {
	      name = bfd_elf_string_from_elf_section (input_bfd,
						      symtab_hdr->sh_link,
						      sym->st_name);
	      if (name == NULL)
		return false;
	      if (*name == '\0')
		name = bfd_section_name (sec);
	    }

	  if (r == bfd_reloc_overflow)
	    {
	      if (converted_reloc)
		{
		  info->callbacks->einfo
		    ("%X%H:", input_bfd, input_section, rel->r_offset);
		  info->callbacks->einfo
		    (_(" failed to convert GOTPCREL relocation against "
		       "'%s'; relink with --no-relax\n"),
		     name);
		  status = false;
		  continue;
		}
	      (*info->callbacks->reloc_overflow)
		(info, (h ? &h->root : NULL), name, howto->name,
		 (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
	    }
	  else
	    {
	      _bfd_error_handler
		/* xgettext:c-format */
		(_("%pB(%pA+%#" PRIx64 "): reloc against `%s': error %d"),
		 input_bfd, input_section,
		 (uint64_t) rel->r_offset, name, (int) r);
	      return false;
	    }
	}

      if (wrel != rel)
	*wrel = *rel;
    }

  if (wrel != rel)
    {
      Elf_Internal_Shdr *rel_hdr;
      size_t deleted = rel - wrel;

      rel_hdr = _bfd_elf_single_rel_hdr (input_section->output_section);
      rel_hdr->sh_size -= rel_hdr->sh_entsize * deleted;
      if (rel_hdr->sh_size == 0)
	{
	  /* It is too late to remove an empty reloc section.  Leave
	     one NONE reloc.
	     ??? What is wrong with an empty section???  */
	  rel_hdr->sh_size = rel_hdr->sh_entsize;
	  deleted -= 1;
	}
      rel_hdr = _bfd_elf_single_rel_hdr (input_section);
      rel_hdr->sh_size -= rel_hdr->sh_entsize * deleted;
      input_section->reloc_count -= deleted;
    }

  return status;
}

/* Finish up dynamic symbol handling.  We set the contents of various
   dynamic sections here.  */

static bool
elf_x86_64_finish_dynamic_symbol (bfd *output_bfd,
				  struct bfd_link_info *info,
				  struct elf_link_hash_entry *h,
				  Elf_Internal_Sym *sym)
{
  struct elf_x86_link_hash_table *htab;
  bool use_plt_second;
  struct elf_x86_link_hash_entry *eh;
  bool local_undefweak;

  htab = elf_x86_hash_table (info, X86_64_ELF_DATA);
  if (htab == NULL)
    return false;

  /* Use the second PLT section only if there is .plt section.  */
  use_plt_second = htab->elf.splt != NULL && htab->plt_second != NULL;

  eh = (struct elf_x86_link_hash_entry *) h;
  if (eh->no_finish_dynamic_symbol)
    abort ();

  /* We keep PLT/GOT entries without dynamic PLT/GOT relocations for
     resolved undefined weak symbols in executable so that their
     references have value 0 at run-time.  */
  local_undefweak = UNDEFINED_WEAK_RESOLVED_TO_ZERO (info, eh);

  if (h->plt.offset != (bfd_vma) -1)
    {
      bfd_vma plt_index;
      bfd_vma got_offset, plt_offset;
      Elf_Internal_Rela rela;
      bfd_byte *loc;
      asection *plt, *gotplt, *relplt, *resolved_plt;
      const struct elf_backend_data *bed;
      bfd_vma plt_got_pcrel_offset;

      /* When building a static executable, use .iplt, .igot.plt and
	 .rela.iplt sections for STT_GNU_IFUNC symbols.  */
      if (htab->elf.splt != NULL)
	{
	  plt = htab->elf.splt;
	  gotplt = htab->elf.sgotplt;
	  relplt = htab->elf.srelplt;
	}
      else
	{
	  plt = htab->elf.iplt;
	  gotplt = htab->elf.igotplt;
	  relplt = htab->elf.irelplt;
	}

      VERIFY_PLT_ENTRY (info, h, plt, gotplt, relplt, local_undefweak)

      /* Get the index in the procedure linkage table which
	 corresponds to this symbol.  This is the index of this symbol
	 in all the symbols for which we are making plt entries.  The
	 first entry in the procedure linkage table is reserved.

	 Get the offset into the .got table of the entry that
	 corresponds to this function.	Each .got entry is GOT_ENTRY_SIZE
	 bytes. The first three are reserved for the dynamic linker.

	 For static executables, we don't reserve anything.  */

      if (plt == htab->elf.splt)
	{
	  got_offset = (h->plt.offset / htab->plt.plt_entry_size
			- htab->plt.has_plt0);
	  got_offset = (got_offset + 3) * GOT_ENTRY_SIZE;
	}
      else
	{
	  got_offset = h->plt.offset / htab->plt.plt_entry_size;
	  got_offset = got_offset * GOT_ENTRY_SIZE;
	}

      /* Fill in the entry in the procedure linkage table.  */
      memcpy (plt->contents + h->plt.offset, htab->plt.plt_entry,
	      htab->plt.plt_entry_size);
      if (use_plt_second)
	{
	  memcpy (htab->plt_second->contents + eh->plt_second.offset,
		  htab->non_lazy_plt->plt_entry,
		  htab->non_lazy_plt->plt_entry_size);

	  resolved_plt = htab->plt_second;
	  plt_offset = eh->plt_second.offset;
	}
      else
	{
	  resolved_plt = plt;
	  plt_offset = h->plt.offset;
	}

      /* Insert the relocation positions of the plt section.  */

      /* Put offset the PC-relative instruction referring to the GOT entry,
	 subtracting the size of that instruction.  */
      plt_got_pcrel_offset = (gotplt->output_section->vma
			      + gotplt->output_offset
			      + got_offset
			      - resolved_plt->output_section->vma
			      - resolved_plt->output_offset
			      - plt_offset
			      - htab->plt.plt_got_insn_size);

      /* Check PC-relative offset overflow in PLT entry.  */
      if ((plt_got_pcrel_offset + 0x80000000) > 0xffffffff)
	/* xgettext:c-format */
	info->callbacks->einfo (_("%F%pB: PC-relative offset overflow in PLT entry for `%s'\n"),
				output_bfd, h->root.root.string);

      bfd_put_32 (output_bfd, plt_got_pcrel_offset,
		  (resolved_plt->contents + plt_offset
		   + htab->plt.plt_got_offset));

      /* Fill in the entry in the global offset table, initially this
	 points to the second part of the PLT entry.  Leave the entry
	 as zero for undefined weak symbol in PIE.  No PLT relocation
	 against undefined weak symbol in PIE.  */
      if (!local_undefweak)
	{
	  if (htab->plt.has_plt0)
	    bfd_put_64 (output_bfd, (plt->output_section->vma
				     + plt->output_offset
				     + h->plt.offset
				     + htab->lazy_plt->plt_lazy_offset),
			gotplt->contents + got_offset);

	  /* Fill in the entry in the .rela.plt section.  */
	  rela.r_offset = (gotplt->output_section->vma
			   + gotplt->output_offset
			   + got_offset);
	  if (PLT_LOCAL_IFUNC_P (info, h))
	    {
	      info->callbacks->minfo (_("Local IFUNC function `%s' in %pB\n"),
				      h->root.root.string,
				      h->root.u.def.section->owner);

	      /* If an STT_GNU_IFUNC symbol is locally defined, generate
		 R_X86_64_IRELATIVE instead of R_X86_64_JUMP_SLOT.  */
	      rela.r_info = htab->r_info (0, R_X86_64_IRELATIVE);
	      rela.r_addend = (h->root.u.def.value
			       + h->root.u.def.section->output_section->vma
			       + h->root.u.def.section->output_offset);

	      if (htab->params->report_relative_reloc)
		_bfd_x86_elf_link_report_relative_reloc
		  (info, relplt, h, sym, "R_X86_64_IRELATIVE", &rela);

	      /* R_X86_64_IRELATIVE comes last.  */
	      plt_index = htab->next_irelative_index--;
	    }
	  else
	    {
	      rela.r_info = htab->r_info (h->dynindx, R_X86_64_JUMP_SLOT);
	      rela.r_addend = 0;
	      plt_index = htab->next_jump_slot_index++;
	    }

	  /* Don't fill the second and third slots in PLT entry for
	     static executables nor without PLT0.  */
	  if (plt == htab->elf.splt && htab->plt.has_plt0)
	    {
	      bfd_vma plt0_offset
		= h->plt.offset + htab->lazy_plt->plt_plt_insn_end;

	      /* Put relocation index.  */
	      bfd_put_32 (output_bfd, plt_index,
			  (plt->contents + h->plt.offset
			   + htab->lazy_plt->plt_reloc_offset));

	      /* Put offset for jmp .PLT0 and check for overflow.  We don't
		 check relocation index for overflow since branch displacement
		 will overflow first.  */
	      if (plt0_offset > 0x80000000)
		/* xgettext:c-format */
		info->callbacks->einfo (_("%F%pB: branch displacement overflow in PLT entry for `%s'\n"),
					output_bfd, h->root.root.string);
	      bfd_put_32 (output_bfd, - plt0_offset,
			  (plt->contents + h->plt.offset
			   + htab->lazy_plt->plt_plt_offset));
	    }

	  bed = get_elf_backend_data (output_bfd);
	  loc = relplt->contents + plt_index * bed->s->sizeof_rela;
	  bed->s->swap_reloca_out (output_bfd, &rela, loc);
	}
    }
  else if (eh->plt_got.offset != (bfd_vma) -1)
    {
      bfd_vma got_offset, plt_offset;
      asection *plt, *got;
      bool got_after_plt;
      int32_t got_pcrel_offset;

      /* Set the entry in the GOT procedure linkage table.  */
      plt = htab->plt_got;
      got = htab->elf.sgot;
      got_offset = h->got.offset;

      if (got_offset == (bfd_vma) -1
	  || (h->type == STT_GNU_IFUNC && h->def_regular)
	  || plt == NULL
	  || got == NULL)
	abort ();

      /* Use the non-lazy PLT entry template for the GOT PLT since they
	 are the identical.  */
      /* Fill in the entry in the GOT procedure linkage table.  */
      plt_offset = eh->plt_got.offset;
      memcpy (plt->contents + plt_offset,
	      htab->non_lazy_plt->plt_entry,
	      htab->non_lazy_plt->plt_entry_size);

      /* Put offset the PC-relative instruction referring to the GOT
	 entry, subtracting the size of that instruction.  */
      got_pcrel_offset = (got->output_section->vma
			  + got->output_offset
			  + got_offset
			  - plt->output_section->vma
			  - plt->output_offset
			  - plt_offset
			  - htab->non_lazy_plt->plt_got_insn_size);

      /* Check PC-relative offset overflow in GOT PLT entry.  */
      got_after_plt = got->output_section->vma > plt->output_section->vma;
      if ((got_after_plt && got_pcrel_offset < 0)
	  || (!got_after_plt && got_pcrel_offset > 0))
	/* xgettext:c-format */
	info->callbacks->einfo (_("%F%pB: PC-relative offset overflow in GOT PLT entry for `%s'\n"),
				output_bfd, h->root.root.string);

      bfd_put_32 (output_bfd, got_pcrel_offset,
		  (plt->contents + plt_offset
		   + htab->non_lazy_plt->plt_got_offset));
    }

  if (!local_undefweak
      && !h->def_regular
      && (h->plt.offset != (bfd_vma) -1
	  || eh->plt_got.offset != (bfd_vma) -1))
    {
      /* Mark the symbol as undefined, rather than as defined in
	 the .plt section.  Leave the value if there were any
	 relocations where pointer equality matters (this is a clue
	 for the dynamic linker, to make function pointer
	 comparisons work between an application and shared
	 library), otherwise set it to zero.  If a function is only
	 called from a binary, there is no need to slow down
	 shared libraries because of that.  */
      sym->st_shndx = SHN_UNDEF;
      if (!h->pointer_equality_needed)
	sym->st_value = 0;
    }

  _bfd_x86_elf_link_fixup_ifunc_symbol (info, htab, h, sym);

  /* Don't generate dynamic GOT relocation against undefined weak
     symbol in executable.  */
  if (h->got.offset != (bfd_vma) -1
      && ! GOT_TLS_GD_ANY_P (elf_x86_hash_entry (h)->tls_type)
      && elf_x86_hash_entry (h)->tls_type != GOT_TLS_IE
      && !local_undefweak)
    {
      Elf_Internal_Rela rela;
      asection *relgot = htab->elf.srelgot;
      const char *relative_reloc_name = NULL;

      /* This symbol has an entry in the global offset table.  Set it
	 up.  */
      if (htab->elf.sgot == NULL || htab->elf.srelgot == NULL)
	abort ();

      rela.r_offset = (htab->elf.sgot->output_section->vma
		       + htab->elf.sgot->output_offset
		       + (h->got.offset &~ (bfd_vma) 1));

      /* If this is a static link, or it is a -Bsymbolic link and the
	 symbol is defined locally or was forced to be local because
	 of a version file, we just want to emit a RELATIVE reloc.
	 The entry in the global offset table will already have been
	 initialized in the relocate_section function.  */
      if (h->def_regular
	  && h->type == STT_GNU_IFUNC)
	{
	  if (h->plt.offset == (bfd_vma) -1)
	    {
	      /* STT_GNU_IFUNC is referenced without PLT.  */
	      if (htab->elf.splt == NULL)
		{
		  /* use .rel[a].iplt section to store .got relocations
		     in static executable.  */
		  relgot = htab->elf.irelplt;
		}
	      if (SYMBOL_REFERENCES_LOCAL_P (info, h))
		{
		  info->callbacks->minfo (_("Local IFUNC function `%s' in %pB\n"),
					  h->root.root.string,
					  h->root.u.def.section->owner);

		  rela.r_info = htab->r_info (0,
					      R_X86_64_IRELATIVE);
		  rela.r_addend = (h->root.u.def.value
				   + h->root.u.def.section->output_section->vma
				   + h->root.u.def.section->output_offset);
		  relative_reloc_name = "R_X86_64_IRELATIVE";
		}
	      else
		goto do_glob_dat;
	    }
	  else if (bfd_link_pic (info))
	    {
	      /* Generate R_X86_64_GLOB_DAT.  */
	      goto do_glob_dat;
	    }
	  else
	    {
	      asection *plt;
	      bfd_vma plt_offset;

	      if (!h->pointer_equality_needed)
		abort ();

	      /* For non-shared object, we can't use .got.plt, which
		 contains the real function addres if we need pointer
		 equality.  We load the GOT entry with the PLT entry.  */
	      if (htab->plt_second != NULL)
		{
		  plt = htab->plt_second;
		  plt_offset = eh->plt_second.offset;
		}
	      else
		{
		  plt = htab->elf.splt ? htab->elf.splt : htab->elf.iplt;
		  plt_offset =  h->plt.offset;
		}
	      bfd_put_64 (output_bfd, (plt->output_section->vma
				       + plt->output_offset
				       + plt_offset),
			  htab->elf.sgot->contents + h->got.offset);
	      return true;
	    }
	}
      else if (bfd_link_pic (info)
	       && SYMBOL_REFERENCES_LOCAL_P (info, h))
	{
	  if (!SYMBOL_DEFINED_NON_SHARED_P (h))
	    return false;
	  BFD_ASSERT((h->got.offset & 1) != 0);
	  rela.r_info = htab->r_info (0, R_X86_64_RELATIVE);
	  rela.r_addend = (h->root.u.def.value
			   + h->root.u.def.section->output_section->vma
			   + h->root.u.def.section->output_offset);
	  relative_reloc_name = "R_X86_64_RELATIVE";
	}
      else
	{
	  BFD_ASSERT((h->got.offset & 1) == 0);
	do_glob_dat:
	  bfd_put_64 (output_bfd, (bfd_vma) 0,
		      htab->elf.sgot->contents + h->got.offset);
	  rela.r_info = htab->r_info (h->dynindx, R_X86_64_GLOB_DAT);
	  rela.r_addend = 0;
	}

      if (relative_reloc_name != NULL
	  && htab->params->report_relative_reloc)
	_bfd_x86_elf_link_report_relative_reloc
	  (info, relgot, h, sym, relative_reloc_name, &rela);

      elf_append_rela (output_bfd, relgot, &rela);
    }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;
      asection *s;

      /* This symbol needs a copy reloc.  Set it up.  */
      VERIFY_COPY_RELOC (h, htab)

      rela.r_offset = (h->root.u.def.value
		       + h->root.u.def.section->output_section->vma
		       + h->root.u.def.section->output_offset);
      rela.r_info = htab->r_info (h->dynindx, R_X86_64_COPY);
      rela.r_addend = 0;
      if (h->root.u.def.section == htab->elf.sdynrelro)
	s = htab->elf.sreldynrelro;
      else
	s = htab->elf.srelbss;
      elf_append_rela (output_bfd, s, &rela);
    }

  return true;
}

/* Finish up local dynamic symbol handling.  We set the contents of
   various dynamic sections here.  */

static int
elf_x86_64_finish_local_dynamic_symbol (void **slot, void *inf)
{
  struct elf_link_hash_entry *h
    = (struct elf_link_hash_entry *) *slot;
  struct bfd_link_info *info
    = (struct bfd_link_info *) inf;

  return elf_x86_64_finish_dynamic_symbol (info->output_bfd,
					   info, h, NULL);
}

/* Finish up undefined weak symbol handling in PIE.  Fill its PLT entry
   here since undefined weak symbol may not be dynamic and may not be
   called for elf_x86_64_finish_dynamic_symbol.  */

static bool
elf_x86_64_pie_finish_undefweak_symbol (struct bfd_hash_entry *bh,
					void *inf)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *) bh;
  struct bfd_link_info *info = (struct bfd_link_info *) inf;

  if (h->root.type != bfd_link_hash_undefweak
      || h->dynindx != -1)
    return true;

  return elf_x86_64_finish_dynamic_symbol (info->output_bfd,
					   info, h, NULL);
}

/* Used to decide how to sort relocs in an optimal manner for the
   dynamic linker, before writing them out.  */

static enum elf_reloc_type_class
elf_x86_64_reloc_type_class (const struct bfd_link_info *info,
			     const asection *rel_sec ATTRIBUTE_UNUSED,
			     const Elf_Internal_Rela *rela)
{
  bfd *abfd = info->output_bfd;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  struct elf_x86_link_hash_table *htab
    = elf_x86_hash_table (info, X86_64_ELF_DATA);

  if (htab->elf.dynsym != NULL
      && htab->elf.dynsym->contents != NULL)
    {
      /* Check relocation against STT_GNU_IFUNC symbol if there are
	 dynamic symbols.  */
      unsigned long r_symndx = htab->r_sym (rela->r_info);
      if (r_symndx != STN_UNDEF)
	{
	  Elf_Internal_Sym sym;
	  if (!bed->s->swap_symbol_in (abfd,
				       (htab->elf.dynsym->contents
					+ r_symndx * bed->s->sizeof_sym),
				       0, &sym))
	    abort ();

	  if (ELF_ST_TYPE (sym.st_info) == STT_GNU_IFUNC)
	    return reloc_class_ifunc;
	}
    }

  switch ((int) ELF32_R_TYPE (rela->r_info))
    {
    case R_X86_64_IRELATIVE:
      return reloc_class_ifunc;
    case R_X86_64_RELATIVE:
    case R_X86_64_RELATIVE64:
      return reloc_class_relative;
    case R_X86_64_JUMP_SLOT:
      return reloc_class_plt;
    case R_X86_64_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

/* Finish up the dynamic sections.  */

static bool
elf_x86_64_finish_dynamic_sections (bfd *output_bfd,
				    struct bfd_link_info *info)
{
  struct elf_x86_link_hash_table *htab;

  htab = _bfd_x86_elf_finish_dynamic_sections (output_bfd, info);
  if (htab == NULL)
    return false;

  if (! htab->elf.dynamic_sections_created)
    return true;

  if (htab->elf.splt && htab->elf.splt->size > 0)
    {
      elf_section_data (htab->elf.splt->output_section)
	->this_hdr.sh_entsize = htab->plt.plt_entry_size;

      if (htab->plt.has_plt0)
	{
	  /* Fill in the special first entry in the procedure linkage
	     table.  */
	  memcpy (htab->elf.splt->contents,
		  htab->lazy_plt->plt0_entry,
		  htab->lazy_plt->plt0_entry_size);
	  /* Add offset for pushq GOT+8(%rip), since the instruction
	     uses 6 bytes subtract this value.  */
	  bfd_put_32 (output_bfd,
		      (htab->elf.sgotplt->output_section->vma
		       + htab->elf.sgotplt->output_offset
		       + 8
		       - htab->elf.splt->output_section->vma
		       - htab->elf.splt->output_offset
		       - 6),
		      (htab->elf.splt->contents
		       + htab->lazy_plt->plt0_got1_offset));
	  /* Add offset for the PC-relative instruction accessing
	     GOT+16, subtracting the offset to the end of that
	     instruction.  */
	  bfd_put_32 (output_bfd,
		      (htab->elf.sgotplt->output_section->vma
		       + htab->elf.sgotplt->output_offset
		       + 16
		       - htab->elf.splt->output_section->vma
		       - htab->elf.splt->output_offset
		       - htab->lazy_plt->plt0_got2_insn_end),
		      (htab->elf.splt->contents
		       + htab->lazy_plt->plt0_got2_offset));
	}

      if (htab->elf.tlsdesc_plt)
	{
	  bfd_put_64 (output_bfd, (bfd_vma) 0,
		      htab->elf.sgot->contents + htab->elf.tlsdesc_got);

	  memcpy (htab->elf.splt->contents + htab->elf.tlsdesc_plt,
		  htab->lazy_plt->plt_tlsdesc_entry,
		  htab->lazy_plt->plt_tlsdesc_entry_size);

	  /* Add offset for pushq GOT+8(%rip), since ENDBR64 uses 4
	     bytes and the instruction uses 6 bytes, subtract these
	     values.  */
	  bfd_put_32 (output_bfd,
		      (htab->elf.sgotplt->output_section->vma
		       + htab->elf.sgotplt->output_offset
		       + 8
		       - htab->elf.splt->output_section->vma
		       - htab->elf.splt->output_offset
		       - htab->elf.tlsdesc_plt
		       - htab->lazy_plt->plt_tlsdesc_got1_insn_end),
		      (htab->elf.splt->contents
		       + htab->elf.tlsdesc_plt
		       + htab->lazy_plt->plt_tlsdesc_got1_offset));
	  /* Add offset for indirect branch via GOT+TDG, where TDG
	     stands for htab->tlsdesc_got, subtracting the offset
	     to the end of that instruction.  */
	  bfd_put_32 (output_bfd,
		      (htab->elf.sgot->output_section->vma
		       + htab->elf.sgot->output_offset
		       + htab->elf.tlsdesc_got
		       - htab->elf.splt->output_section->vma
		       - htab->elf.splt->output_offset
		       - htab->elf.tlsdesc_plt
		       - htab->lazy_plt->plt_tlsdesc_got2_insn_end),
		      (htab->elf.splt->contents
		       + htab->elf.tlsdesc_plt
		       + htab->lazy_plt->plt_tlsdesc_got2_offset));
	}
    }

  /* Fill PLT entries for undefined weak symbols in PIE.  */
  if (bfd_link_pie (info))
    bfd_hash_traverse (&info->hash->table,
		       elf_x86_64_pie_finish_undefweak_symbol,
		       info);

  return true;
}

/* Fill PLT/GOT entries and allocate dynamic relocations for local
   STT_GNU_IFUNC symbols, which aren't in the ELF linker hash table.
   It has to be done before elf_link_sort_relocs is called so that
   dynamic relocations are properly sorted.  */

static bool
elf_x86_64_output_arch_local_syms
  (bfd *output_bfd ATTRIBUTE_UNUSED,
   struct bfd_link_info *info,
   void *flaginfo ATTRIBUTE_UNUSED,
   int (*func) (void *, const char *,
		Elf_Internal_Sym *,
		asection *,
		struct elf_link_hash_entry *) ATTRIBUTE_UNUSED)
{
  struct elf_x86_link_hash_table *htab
    = elf_x86_hash_table (info, X86_64_ELF_DATA);
  if (htab == NULL)
    return false;

  /* Fill PLT and GOT entries for local STT_GNU_IFUNC symbols.  */
  htab_traverse (htab->loc_hash_table,
		 elf_x86_64_finish_local_dynamic_symbol,
		 info);

  return true;
}

/* Similar to _bfd_elf_get_synthetic_symtab.  Support PLTs with all
   dynamic relocations.   */

static long
elf_x86_64_get_synthetic_symtab (bfd *abfd,
				 long symcount ATTRIBUTE_UNUSED,
				 asymbol **syms ATTRIBUTE_UNUSED,
				 long dynsymcount,
				 asymbol **dynsyms,
				 asymbol **ret)
{
  long count, i, n;
  int j;
  bfd_byte *plt_contents;
  long relsize;
  const struct elf_x86_lazy_plt_layout *lazy_plt;
  const struct elf_x86_non_lazy_plt_layout *non_lazy_plt;
  const struct elf_x86_lazy_plt_layout *lazy_bnd_plt;
  const struct elf_x86_non_lazy_plt_layout *non_lazy_bnd_plt;
  const struct elf_x86_lazy_plt_layout *lazy_ibt_plt;
  const struct elf_x86_non_lazy_plt_layout *non_lazy_ibt_plt;
  asection *plt;
  enum elf_x86_plt_type plt_type;
  struct elf_x86_plt plts[] =
    {
      { ".plt", NULL, NULL, plt_unknown, 0, 0, 0, 0 },
      { ".plt.got", NULL, NULL, plt_non_lazy, 0, 0, 0, 0 },
      { ".plt.sec", NULL, NULL, plt_second, 0, 0, 0, 0 },
      { ".plt.bnd", NULL, NULL, plt_second, 0, 0, 0, 0 },
      { NULL, NULL, NULL, plt_non_lazy, 0, 0, 0, 0 }
    };

  *ret = NULL;

  if ((abfd->flags & (DYNAMIC | EXEC_P)) == 0)
    return 0;

  if (dynsymcount <= 0)
    return 0;

  relsize = bfd_get_dynamic_reloc_upper_bound (abfd);
  if (relsize <= 0)
    return -1;

  lazy_plt = &elf_x86_64_lazy_plt;
  non_lazy_plt = &elf_x86_64_non_lazy_plt;
  lazy_bnd_plt = &elf_x86_64_lazy_bnd_plt;
  non_lazy_bnd_plt = &elf_x86_64_non_lazy_bnd_plt;
  if (ABI_64_P (abfd))
    {
      lazy_ibt_plt = &elf_x86_64_lazy_ibt_plt;
      non_lazy_ibt_plt = &elf_x86_64_non_lazy_ibt_plt;
    }
  else
    {
      lazy_ibt_plt = &elf_x32_lazy_ibt_plt;
      non_lazy_ibt_plt = &elf_x32_non_lazy_ibt_plt;
    }

  count = 0;
  for (j = 0; plts[j].name != NULL; j++)
    {
      plt = bfd_get_section_by_name (abfd, plts[j].name);
      if (plt == NULL || plt->size == 0)
	continue;

      /* Get the PLT section contents.  */
      if (!bfd_malloc_and_get_section (abfd, plt, &plt_contents))
	break;

      /* Check what kind of PLT it is.  */
      plt_type = plt_unknown;
      if (plts[j].type == plt_unknown
	  && (plt->size >= (lazy_plt->plt_entry_size
			    + lazy_plt->plt_entry_size)))
	{
	  /* Match lazy PLT first.  Need to check the first two
	     instructions.   */
	  if ((memcmp (plt_contents, lazy_plt->plt0_entry,
		       lazy_plt->plt0_got1_offset) == 0)
	      && (memcmp (plt_contents + 6, lazy_plt->plt0_entry + 6,
			  2) == 0))
	    plt_type = plt_lazy;
	  else if (lazy_bnd_plt != NULL
		   && (memcmp (plt_contents, lazy_bnd_plt->plt0_entry,
			       lazy_bnd_plt->plt0_got1_offset) == 0)
		   && (memcmp (plt_contents + 6,
			       lazy_bnd_plt->plt0_entry + 6, 3) == 0))
	    {
	      plt_type = plt_lazy | plt_second;
	      /* The fist entry in the lazy IBT PLT is the same as the
		 lazy BND PLT.  */
	      if ((memcmp (plt_contents + lazy_ibt_plt->plt_entry_size,
			   lazy_ibt_plt->plt_entry,
			   lazy_ibt_plt->plt_got_offset) == 0))
		lazy_plt = lazy_ibt_plt;
	      else
		lazy_plt = lazy_bnd_plt;
	    }
	}

      if (non_lazy_plt != NULL
	  && (plt_type == plt_unknown || plt_type == plt_non_lazy)
	  && plt->size >= non_lazy_plt->plt_entry_size)
	{
	  /* Match non-lazy PLT.  */
	  if (memcmp (plt_contents, non_lazy_plt->plt_entry,
		      non_lazy_plt->plt_got_offset) == 0)
	    plt_type = plt_non_lazy;
	}

      if (plt_type == plt_unknown || plt_type == plt_second)
	{
	  if (non_lazy_bnd_plt != NULL
	      && plt->size >= non_lazy_bnd_plt->plt_entry_size
	      && (memcmp (plt_contents, non_lazy_bnd_plt->plt_entry,
			  non_lazy_bnd_plt->plt_got_offset) == 0))
	    {
	      /* Match BND PLT.  */
	      plt_type = plt_second;
	      non_lazy_plt = non_lazy_bnd_plt;
	    }
	  else if (non_lazy_ibt_plt != NULL
		   && plt->size >= non_lazy_ibt_plt->plt_entry_size
		   && (memcmp (plt_contents,
			       non_lazy_ibt_plt->plt_entry,
			       non_lazy_ibt_plt->plt_got_offset) == 0))
	    {
	      /* Match IBT PLT.  */
	      plt_type = plt_second;
	      non_lazy_plt = non_lazy_ibt_plt;
	    }
	}

      if (plt_type == plt_unknown)
	{
	  free (plt_contents);
	  continue;
	}

      plts[j].sec = plt;
      plts[j].type = plt_type;

      if ((plt_type & plt_lazy))
	{
	  plts[j].plt_got_offset = lazy_plt->plt_got_offset;
	  plts[j].plt_got_insn_size = lazy_plt->plt_got_insn_size;
	  plts[j].plt_entry_size = lazy_plt->plt_entry_size;
	  /* Skip PLT0 in lazy PLT.  */
	  i = 1;
	}
      else
	{
	  plts[j].plt_got_offset = non_lazy_plt->plt_got_offset;
	  plts[j].plt_got_insn_size = non_lazy_plt->plt_got_insn_size;
	  plts[j].plt_entry_size = non_lazy_plt->plt_entry_size;
	  i = 0;
	}

      /* Skip lazy PLT when the second PLT is used.  */
      if (plt_type == (plt_lazy | plt_second))
	plts[j].count = 0;
      else
	{
	  n = plt->size / plts[j].plt_entry_size;
	  plts[j].count = n;
	  count += n - i;
	}

      plts[j].contents = plt_contents;
    }

  return _bfd_x86_elf_get_synthetic_symtab (abfd, count, relsize,
					    (bfd_vma) 0, plts, dynsyms,
					    ret);
}

/* Handle an x86-64 specific section when reading an object file.  This
   is called when elfcode.h finds a section with an unknown type.  */

static bool
elf_x86_64_section_from_shdr (bfd *abfd, Elf_Internal_Shdr *hdr,
			      const char *name, int shindex)
{
  if (hdr->sh_type != SHT_X86_64_UNWIND)
    return false;

  if (! _bfd_elf_make_section_from_shdr (abfd, hdr, name, shindex))
    return false;

  return true;
}

/* Hook called by the linker routine which adds symbols from an object
   file.  We use it to put SHN_X86_64_LCOMMON items in .lbss, instead
   of .bss.  */

static bool
elf_x86_64_add_symbol_hook (bfd *abfd,
			    struct bfd_link_info *info ATTRIBUTE_UNUSED,
			    Elf_Internal_Sym *sym,
			    const char **namep ATTRIBUTE_UNUSED,
			    flagword *flagsp ATTRIBUTE_UNUSED,
			    asection **secp,
			    bfd_vma *valp)
{
  asection *lcomm;

  switch (sym->st_shndx)
    {
    case SHN_X86_64_LCOMMON:
      lcomm = bfd_get_section_by_name (abfd, "LARGE_COMMON");
      if (lcomm == NULL)
	{
	  lcomm = bfd_make_section_with_flags (abfd,
					       "LARGE_COMMON",
					       (SEC_ALLOC
						| SEC_IS_COMMON
						| SEC_LINKER_CREATED));
	  if (lcomm == NULL)
	    return false;
	  elf_section_flags (lcomm) |= SHF_X86_64_LARGE;
	}
      *secp = lcomm;
      *valp = sym->st_size;
      return true;
    }

  return true;
}


/* Given a BFD section, try to locate the corresponding ELF section
   index.  */

static bool
elf_x86_64_elf_section_from_bfd_section (bfd *abfd ATTRIBUTE_UNUSED,
					 asection *sec, int *index_return)
{
  if (sec == &_bfd_elf_large_com_section)
    {
      *index_return = SHN_X86_64_LCOMMON;
      return true;
    }
  return false;
}

/* Process a symbol.  */

static void
elf_x86_64_symbol_processing (bfd *abfd ATTRIBUTE_UNUSED,
			      asymbol *asym)
{
  elf_symbol_type *elfsym = (elf_symbol_type *) asym;

  switch (elfsym->internal_elf_sym.st_shndx)
    {
    case SHN_X86_64_LCOMMON:
      asym->section = &_bfd_elf_large_com_section;
      asym->value = elfsym->internal_elf_sym.st_size;
      /* Common symbol doesn't set BSF_GLOBAL.  */
      asym->flags &= ~BSF_GLOBAL;
      break;
    }
}

static bool
elf_x86_64_common_definition (Elf_Internal_Sym *sym)
{
  return (sym->st_shndx == SHN_COMMON
	  || sym->st_shndx == SHN_X86_64_LCOMMON);
}

static unsigned int
elf_x86_64_common_section_index (asection *sec)
{
  if ((elf_section_flags (sec) & SHF_X86_64_LARGE) == 0)
    return SHN_COMMON;
  else
    return SHN_X86_64_LCOMMON;
}

static asection *
elf_x86_64_common_section (asection *sec)
{
  if ((elf_section_flags (sec) & SHF_X86_64_LARGE) == 0)
    return bfd_com_section_ptr;
  else
    return &_bfd_elf_large_com_section;
}

static bool
elf_x86_64_merge_symbol (struct elf_link_hash_entry *h,
			 const Elf_Internal_Sym *sym,
			 asection **psec,
			 bool newdef,
			 bool olddef,
			 bfd *oldbfd,
			 const asection *oldsec)
{
  /* A normal common symbol and a large common symbol result in a
     normal common symbol.  We turn the large common symbol into a
     normal one.  */
  if (!olddef
      && h->root.type == bfd_link_hash_common
      && !newdef
      && bfd_is_com_section (*psec)
      && oldsec != *psec)
    {
      if (sym->st_shndx == SHN_COMMON
	  && (elf_section_flags (oldsec) & SHF_X86_64_LARGE) != 0)
	{
	  h->root.u.c.p->section
	    = bfd_make_section_old_way (oldbfd, "COMMON");
	  h->root.u.c.p->section->flags = SEC_ALLOC;
	}
      else if (sym->st_shndx == SHN_X86_64_LCOMMON
	       && (elf_section_flags (oldsec) & SHF_X86_64_LARGE) == 0)
	*psec = bfd_com_section_ptr;
    }

  return true;
}

static int
elf_x86_64_additional_program_headers (bfd *abfd,
				       struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  asection *s;
  int count = 0;

  /* Check to see if we need a large readonly segment.  */
  s = bfd_get_section_by_name (abfd, ".lrodata");
  if (s && (s->flags & SEC_LOAD))
    count++;

  /* Check to see if we need a large data segment.  Since .lbss sections
     is placed right after the .bss section, there should be no need for
     a large data segment just because of .lbss.  */
  s = bfd_get_section_by_name (abfd, ".ldata");
  if (s && (s->flags & SEC_LOAD))
    count++;

  return count;
}

/* Return TRUE iff relocations for INPUT are compatible with OUTPUT. */

static bool
elf_x86_64_relocs_compatible (const bfd_target *input,
			      const bfd_target *output)
{
  return ((xvec_get_elf_backend_data (input)->s->elfclass
	   == xvec_get_elf_backend_data (output)->s->elfclass)
	  && _bfd_elf_relocs_compatible (input, output));
}

/* Set up x86-64 GNU properties.  Return the first relocatable ELF input
   with GNU properties if found.  Otherwise, return NULL.  */

static bfd *
elf_x86_64_link_setup_gnu_properties (struct bfd_link_info *info)
{
  struct elf_x86_init_table init_table;
  const struct elf_backend_data *bed;
  struct elf_x86_link_hash_table *htab;

  if ((int) R_X86_64_standard >= (int) R_X86_64_converted_reloc_bit
      || (int) R_X86_64_max <= (int) R_X86_64_converted_reloc_bit
      || ((int) (R_X86_64_GNU_VTINHERIT | R_X86_64_converted_reloc_bit)
	  != (int) R_X86_64_GNU_VTINHERIT)
      || ((int) (R_X86_64_GNU_VTENTRY | R_X86_64_converted_reloc_bit)
	  != (int) R_X86_64_GNU_VTENTRY))
    abort ();

  /* This is unused for x86-64.  */
  init_table.plt0_pad_byte = 0x90;

  bed = get_elf_backend_data (info->output_bfd);
  htab = elf_x86_hash_table (info, bed->target_id);
  if (!htab)
    abort ();
  if (htab->params->bndplt)
    {
      init_table.lazy_plt = &elf_x86_64_lazy_bnd_plt;
      init_table.non_lazy_plt = &elf_x86_64_non_lazy_bnd_plt;
    }
  else
    {
      init_table.lazy_plt = &elf_x86_64_lazy_plt;
      init_table.non_lazy_plt = &elf_x86_64_non_lazy_plt;
    }

  if (ABI_64_P (info->output_bfd))
    {
      init_table.lazy_ibt_plt = &elf_x86_64_lazy_ibt_plt;
      init_table.non_lazy_ibt_plt = &elf_x86_64_non_lazy_ibt_plt;
    }
  else
    {
      init_table.lazy_ibt_plt = &elf_x32_lazy_ibt_plt;
      init_table.non_lazy_ibt_plt = &elf_x32_non_lazy_ibt_plt;
    }

  if (ABI_64_P (info->output_bfd))
    {
      init_table.r_info = elf64_r_info;
      init_table.r_sym = elf64_r_sym;
    }
  else
    {
      init_table.r_info = elf32_r_info;
      init_table.r_sym = elf32_r_sym;
    }

  return _bfd_x86_elf_link_setup_gnu_properties (info, &init_table);
}

static const struct bfd_elf_special_section
elf_x86_64_special_sections[]=
{
  { STRING_COMMA_LEN (".gnu.linkonce.lb"), -2, SHT_NOBITS,   SHF_ALLOC + SHF_WRITE + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".gnu.linkonce.lr"), -2, SHT_PROGBITS, SHF_ALLOC + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".gnu.linkonce.lt"), -2, SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".lbss"),		   -2, SHT_NOBITS,   SHF_ALLOC + SHF_WRITE + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".ldata"),	   -2, SHT_PROGBITS, SHF_ALLOC + SHF_WRITE + SHF_X86_64_LARGE},
  { STRING_COMMA_LEN (".lrodata"),	   -2, SHT_PROGBITS, SHF_ALLOC + SHF_X86_64_LARGE},
  { NULL,			0,	    0, 0,	     0 }
};

#define TARGET_LITTLE_SYM		    x86_64_elf64_vec
#define TARGET_LITTLE_NAME		    "elf64-x86-64"
#define ELF_ARCH			    bfd_arch_i386
#define ELF_TARGET_ID			    X86_64_ELF_DATA
#define ELF_MACHINE_CODE		    EM_X86_64
#if DEFAULT_LD_Z_SEPARATE_CODE
# define ELF_MAXPAGESIZE		    0x1000
#else
# define ELF_MAXPAGESIZE		    0x200000
#endif
#define ELF_MINPAGESIZE			    0x1000
#define ELF_COMMONPAGESIZE		    0x1000

#define elf_backend_can_gc_sections	    1
#define elf_backend_can_refcount	    1
#define elf_backend_want_got_plt	    1
#define elf_backend_plt_readonly	    1
#define elf_backend_want_plt_sym	    0
#define elf_backend_got_header_size	    (GOT_ENTRY_SIZE*3)
#define elf_backend_rela_normal		    1
#define elf_backend_plt_alignment	    4
#define elf_backend_extern_protected_data   1
#define elf_backend_caches_rawsize	    1
#define elf_backend_dtrel_excludes_plt	    1
#define elf_backend_want_dynrelro	    1

#define elf_info_to_howto		    elf_x86_64_info_to_howto

#define bfd_elf64_bfd_reloc_type_lookup	    elf_x86_64_reloc_type_lookup
#define bfd_elf64_bfd_reloc_name_lookup \
  elf_x86_64_reloc_name_lookup

#define elf_backend_relocs_compatible	    elf_x86_64_relocs_compatible
#define elf_backend_check_relocs	    elf_x86_64_check_relocs
#define elf_backend_create_dynamic_sections _bfd_elf_create_dynamic_sections
#define elf_backend_finish_dynamic_sections elf_x86_64_finish_dynamic_sections
#define elf_backend_finish_dynamic_symbol   elf_x86_64_finish_dynamic_symbol
#define elf_backend_output_arch_local_syms  elf_x86_64_output_arch_local_syms
#define elf_backend_grok_prstatus	    elf_x86_64_grok_prstatus
#define elf_backend_grok_psinfo		    elf_x86_64_grok_psinfo
#ifdef CORE_HEADER
#define elf_backend_write_core_note	    elf_x86_64_write_core_note
#endif
#define elf_backend_reloc_type_class	    elf_x86_64_reloc_type_class
#define elf_backend_relocate_section	    elf_x86_64_relocate_section
#define elf_backend_init_index_section	    _bfd_elf_init_1_index_section
#define elf_backend_object_p		    elf64_x86_64_elf_object_p
#define bfd_elf64_get_synthetic_symtab	    elf_x86_64_get_synthetic_symtab

#define elf_backend_section_from_shdr \
	elf_x86_64_section_from_shdr

#define elf_backend_section_from_bfd_section \
  elf_x86_64_elf_section_from_bfd_section
#define elf_backend_add_symbol_hook \
  elf_x86_64_add_symbol_hook
#define elf_backend_symbol_processing \
  elf_x86_64_symbol_processing
#define elf_backend_common_section_index \
  elf_x86_64_common_section_index
#define elf_backend_common_section \
  elf_x86_64_common_section
#define elf_backend_common_definition \
  elf_x86_64_common_definition
#define elf_backend_merge_symbol \
  elf_x86_64_merge_symbol
#define elf_backend_special_sections \
  elf_x86_64_special_sections
#define elf_backend_additional_program_headers \
  elf_x86_64_additional_program_headers
#define elf_backend_setup_gnu_properties \
  elf_x86_64_link_setup_gnu_properties
#define elf_backend_hide_symbol \
  _bfd_x86_elf_hide_symbol

#undef	elf64_bed
#define elf64_bed elf64_x86_64_bed

#include "elf64-target.h"

/* CloudABI support.  */

#undef	TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    x86_64_elf64_cloudabi_vec
#undef	TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf64-x86-64-cloudabi"

#undef	ELF_OSABI
#define	ELF_OSABI			    ELFOSABI_CLOUDABI

#undef	elf64_bed
#define elf64_bed elf64_x86_64_cloudabi_bed

#include "elf64-target.h"

/* FreeBSD support.  */

#undef	TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    x86_64_elf64_fbsd_vec
#undef	TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf64-x86-64-freebsd"

#undef	ELF_OSABI
#define	ELF_OSABI			    ELFOSABI_FREEBSD

#undef	elf64_bed
#define elf64_bed elf64_x86_64_fbsd_bed

#include "elf64-target.h"

/* Solaris 2 support.  */

#undef  TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    x86_64_elf64_sol2_vec
#undef  TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf64-x86-64-sol2"

#undef ELF_TARGET_OS
#define	ELF_TARGET_OS			    is_solaris

/* Restore default: we cannot use ELFOSABI_SOLARIS, otherwise ELFOSABI_NONE
   objects won't be recognized.  */
#undef ELF_OSABI

#undef  elf64_bed
#define elf64_bed			    elf64_x86_64_sol2_bed

/* The 64-bit static TLS arena size is rounded to the nearest 16-byte
   boundary.  */
#undef  elf_backend_static_tls_alignment
#define elf_backend_static_tls_alignment    16

/* The Solaris 2 ABI requires a plt symbol on all platforms.

   Cf. Linker and Libraries Guide, Ch. 2, Link-Editor, Generating the Output
   File, p.63.  */
#undef  elf_backend_want_plt_sym
#define elf_backend_want_plt_sym	    1

#undef  elf_backend_strtab_flags
#define elf_backend_strtab_flags	SHF_STRINGS

static bool
elf64_x86_64_copy_solaris_special_section_fields (const bfd *ibfd ATTRIBUTE_UNUSED,
						  bfd *obfd ATTRIBUTE_UNUSED,
						  const Elf_Internal_Shdr *isection ATTRIBUTE_UNUSED,
						  Elf_Internal_Shdr *osection ATTRIBUTE_UNUSED)
{
  /* PR 19938: FIXME: Need to add code for setting the sh_info
     and sh_link fields of Solaris specific section types.  */
  return false;
}

#undef  elf_backend_copy_special_section_fields
#define elf_backend_copy_special_section_fields elf64_x86_64_copy_solaris_special_section_fields

#include "elf64-target.h"

/* Restore defaults.  */
#undef	ELF_OSABI
#undef	elf_backend_static_tls_alignment
#undef	elf_backend_want_plt_sym
#define elf_backend_want_plt_sym	0
#undef  elf_backend_strtab_flags
#undef  elf_backend_copy_special_section_fields

/* Intel L1OM support.  */

static bool
elf64_l1om_elf_object_p (bfd *abfd)
{
  /* Set the right machine number for an L1OM elf64 file.  */
  bfd_default_set_arch_mach (abfd, bfd_arch_l1om, bfd_mach_l1om);
  return true;
}

#undef  TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    l1om_elf64_vec
#undef  TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf64-l1om"
#undef ELF_ARCH
#define ELF_ARCH			    bfd_arch_l1om

#undef	ELF_MACHINE_CODE
#define ELF_MACHINE_CODE		    EM_L1OM

#undef	ELF_OSABI

#undef  elf64_bed
#define elf64_bed elf64_l1om_bed

#undef elf_backend_object_p
#define elf_backend_object_p		    elf64_l1om_elf_object_p

/* Restore defaults.  */
#undef	ELF_MAXPAGESIZE
#undef	ELF_MINPAGESIZE
#undef	ELF_COMMONPAGESIZE
#if DEFAULT_LD_Z_SEPARATE_CODE
# define ELF_MAXPAGESIZE		0x1000
#else
# define ELF_MAXPAGESIZE		0x200000
#endif
#define ELF_MINPAGESIZE			0x1000
#define ELF_COMMONPAGESIZE		0x1000
#undef	elf_backend_plt_alignment
#define elf_backend_plt_alignment	4
#undef ELF_TARGET_OS

#include "elf64-target.h"

/* FreeBSD L1OM support.  */

#undef  TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    l1om_elf64_fbsd_vec
#undef  TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf64-l1om-freebsd"

#undef	ELF_OSABI
#define	ELF_OSABI			    ELFOSABI_FREEBSD

#undef  elf64_bed
#define elf64_bed elf64_l1om_fbsd_bed

#include "elf64-target.h"

/* Intel K1OM support.  */

static bool
elf64_k1om_elf_object_p (bfd *abfd)
{
  /* Set the right machine number for an K1OM elf64 file.  */
  bfd_default_set_arch_mach (abfd, bfd_arch_k1om, bfd_mach_k1om);
  return true;
}

#undef  TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    k1om_elf64_vec
#undef  TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf64-k1om"
#undef ELF_ARCH
#define ELF_ARCH			    bfd_arch_k1om

#undef	ELF_MACHINE_CODE
#define ELF_MACHINE_CODE		    EM_K1OM

#undef	ELF_OSABI

#undef  elf64_bed
#define elf64_bed elf64_k1om_bed

#undef elf_backend_object_p
#define elf_backend_object_p		    elf64_k1om_elf_object_p

#include "elf64-target.h"

/* FreeBSD K1OM support.  */

#undef  TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    k1om_elf64_fbsd_vec
#undef  TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf64-k1om-freebsd"

#undef	ELF_OSABI
#define	ELF_OSABI			    ELFOSABI_FREEBSD

#undef  elf64_bed
#define elf64_bed elf64_k1om_fbsd_bed

#include "elf64-target.h"

/* 32bit x86-64 support.  */

#undef  TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM		    x86_64_elf32_vec
#undef  TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME		    "elf32-x86-64"
#undef	elf32_bed
#define	elf32_bed			    elf32_x86_64_bed

#undef ELF_ARCH
#define ELF_ARCH			    bfd_arch_i386

#undef	ELF_MACHINE_CODE
#define ELF_MACHINE_CODE		    EM_X86_64

#undef	ELF_OSABI

#define bfd_elf32_bfd_reloc_type_lookup	\
  elf_x86_64_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup \
  elf_x86_64_reloc_name_lookup
#define bfd_elf32_get_synthetic_symtab \
  elf_x86_64_get_synthetic_symtab

#undef elf_backend_object_p
#define elf_backend_object_p \
  elf32_x86_64_elf_object_p

#undef elf_backend_bfd_from_remote_memory
#define elf_backend_bfd_from_remote_memory \
  _bfd_elf32_bfd_from_remote_memory

#undef elf_backend_size_info
#define elf_backend_size_info \
  _bfd_elf32_size_info

#include "elf32-target.h"
