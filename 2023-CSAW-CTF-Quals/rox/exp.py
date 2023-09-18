IMP=[]
# init data
with open("./dumped",'rb') as f:
    dt = f.read()
ct = len(dt)//4
DATA = []
from pwn import *
for x in range(ct):
    DATA.append(u32(dt[x*4:x*4+4]))

phw = b"flag{ph3w...u finaLly g0t it! jump into cell wHen U g3t t0 the next cha11}"
def enc(plain):
    for x in range(len(plain)):
        IMP[x]^=plain[x]

    for x in range(74):
        IMP[x]^= DATA[DATA[10*x+12]+plain[x]]
    
    for x in range(5,74):
        for m in range(300):
            IMP[x] ^= (0x20*m)%0x100

    for x in range(74):
        if(phw[x]!=IMP[x]):
            return 1
    return 0
flag = []
for x in phw:
    flag.append(x)
for x in range(5,74):
    for m in range(300):
        flag[x] ^= (0x20*m)%0x100
print(bytes(flag))

IMP = [[0x74,0x71,0x57,0x7a,0x5f,0x38,0x42,0x3f][::-1],
[0x1f,0x63,0x16,0x3d,0x32,0x47,0x44,0x66][::-1],
[0x1c,0x64,0x03,0x2a,0x5c,0x12,0x1a,0x12][::-1],
[0x30,0x3a,0x02,0x4c,0x3f,0x01,0x40,0x15][::-1],
[0x5e,0x48,0x5f,0x19,0x4d,0x69,0x7c,0x1d][::-1],
[0x65,0x4c,0x6b,0x52,0x09,0x17,0x03,0x20][::-1],
[0x2e,0x40,0x28,0x2b,0x5b,0x06,0x48,0x6f][::-1],
[0x6e,0x21,0x56,0x30,0x31,0x16,0x0b,0x4e][::-1],
[0x18,0x3f,0x04,0x10,0x1c,0x4b,0x30,0x2d][::-1],
[0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x41][::-1]]
IMP = [y for x in IMP for y in x]
for l in range(74,75):
    print(l)
    nn=0
    res = []
    for x in range(l): 
        res.append(0)
    for x in range(l):
        fff = 0
        # print(f"{x} ",end='')
        for y in range(0x20,0X7F):
            if(IMP[x]^y^(DATA[DATA[10*x+12]+y])==flag[x]):
                if(fff==1):
                    pass
                    print(x,chr(res[x]),chr(y))
                res[x]=y
                
                fff=1
                # print(f"{chr(y)} ",end='')
        # print("")
        if fff==0:
            nn=1
            break
    if nn ==1:
        continue
    res+=[0]*(74-l)
    for x in range(l,74):
        y = res[x%l]
        print(chr(IMP[x]^(DATA[DATA[10*x+12]+y])))
        if IMP[x]^(DATA[DATA[10*x+12]+y])!=flag[x]:
            nn = 1
            break
    if nn ==1:
        continue
    else:
        print(bytes(res))
"""
aN0ther_HGRRing_or_irhtHiswiTn
aN0ther_HeR=inF_or_NS_tH3swiTn
aN0ther_HeR=inF_or_NS_tH6e_NT&

aN0ther_HeRRing_or_iS_tHis_NTn
csawctf{aN0ther_HeRRing_or_iS_tHis_iT&}
"""

print(bytes(res))
