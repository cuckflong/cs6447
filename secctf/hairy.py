from pwn import *
import re

c = remote("binary.hashbangctf.com", 6001)
c.sendline("a")
c.sendline("a")
print c.recvlines(5)
#reply = c.recvline()
#num = re.search('is (*)', reply).group(0)
#print(num)
c.close()

