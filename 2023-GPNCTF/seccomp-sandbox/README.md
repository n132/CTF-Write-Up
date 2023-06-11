# Attachment

[Tarball](seccomp-sandbox.tar.gz)

# Solution
- Race Condition: The sandbox is implemented at userspace
- Use another process to modify the memory space that is checked by supervisor

# Exploit

[n132.c](n132.c)

[exp.py](exp.py)