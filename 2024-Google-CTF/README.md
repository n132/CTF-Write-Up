# Attachment

[Attachment](knife.zip)

# Vulnerability
- OOB in put
- When the length of plaintext is not 4 bytes, a85 decoding didn't check if it's the last block, so `dec(enc('x')+enc('xxxx')) == dec(enc('xxxx')+enc('x'))`

# Solution

- Fill padding messages
- Overflow to write the hash value of the flag
- dump the flag

# Exploit

[exp.py](exp.py)
