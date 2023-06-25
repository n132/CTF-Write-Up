# Attachment

[zip](GRADEBOOK.zip)

# Solution

- There is no check for `start`
- Set `start` to a fake chunk
- Modify `limit/end` by modifying grade
- Leak `stack` address
- Edit return address on stack to backdoor

# Exploit

[exp.py](exp.py)
