
from pwn import *


debug = 1

if debug :
    io = process('./chal')
else:
    io = remote('155.248.203.119',42051)


payload =
