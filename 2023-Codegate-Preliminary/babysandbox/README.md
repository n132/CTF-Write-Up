# Attachment

[zip](misc-babysandbox-for_user.zip)

# Solution

This challenge allows us to provide our own bpf filter so we can 

1. allow all syscalls 
2. set the return value (≤0) of syscalls

Binary with Fortify mitigation would check if “%n” is on writable memory chunk. so we can hijack openat and let it return 0 while checking /proc/self/maps, which means we can provide the fake content from stdin.

So the whole filter to bypass Fortify is:

```
LD [0]
JEQ 1 0 0x101
RET ALLOW
LD [0x20]
JEQ 1 0 0x80000
RET ALLOW 
RET ERROR 0
```

# Exploit

[exp.py](./exp.py)
