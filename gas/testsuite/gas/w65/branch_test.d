#as:
#objdump:  -dr
#name:  branch_test

.*:     file format elf32-w65

Disassembly of section .text:

00000000 <main>:
   0:   90 fe           bcc     0x0
   2:   b0 fc           bcs     0x0
   4:   f0 fa           beq     0x0
   6:   30 f8           bmi     0x0
   8:   d0 f6           bne     0x0
   a:   10 f4           bpl     0x0
   c:   80 f2           bra     0x0
   e:   50 f0           bvc     0x0
  10:   70 ee           bvs     0x0
  12:   82 eb ff        brl     0x0