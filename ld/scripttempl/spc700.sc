cat << EOF
/*
Copyright 2017 Mads Elvheim / 'Madsy'

Redistribution and use in source and binary forms, with or without modification, are permitted provided
that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*

*/

OUTPUT_FORMAT("coff-spc700")
/* OUTPUT_ARCH(spc700) */
SEARCH_DIR(.)


MEMORY
{
  dpage0 (rw)           : ORIGIN = 0x000000,  LENGTH = 256
  dpage1 (rw)           : ORIGIN = 0x000100,  LENGTH = 256
  ram (rw)              : ORIGIN = 0x000200,  LENGTH = 32256 /* 0x7E00 */
  ipl_rom(r)            : ORIGIN = 0xFFC0,    LENGTH = 64
}

SECTIONS
{
    .text :
    {
        KEEP(*(.vectors .vectors.*))
        *(.text .text.*)
        *(.rodata .rodata.*)
    } > ram = 0xFF
    _text_end = .
    .data :
    {
        *(.data .data.*)
        *(.rodata .rodata.*)
    } > ram = 0x00
    PROVIDE(_data_end = .);
}
EOF
