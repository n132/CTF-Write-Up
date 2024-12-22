# Attachment

[zip](ip_management_system.zip)

# Solution

## Vulnerability:

The start IP was not checked after applying the IP mask to it so there is an underflow on the heap.

This bug was easy to find but the exploitation was complex since it’s a limit underflow: we can only set a range of bits to 1/0. So I nudged the range and performed oob write twice to gain a fake header. 

## Solution:

- Change the header of the current heap chunk → First Free then Retrieve to gain overflow access
- Since we need an additional free out of the challenge (so we can hijack the fd of a freed chunk.) we change the top chunk header to perform a free (house-of-orange). Then we have `A→B` in tcache
- Overflow `A` to set its `fd` to an arbitrary address then we have AAW as well as AAR
- 2.35 libc is vulnerable to Libc-GOT-Hijacking so we choose a target to trigger.
    - However, we only have bit-level AAW (write one bit every modification).
    - So we have to find a trigger function that is not called in the path to trigger the arbitrary address bit write.
    - strtok is good and it uses a function whose got is writable. →`strtok(”/bin/sh;-”)`to get shell.

# Exploit

[exp.py](exp.py)
