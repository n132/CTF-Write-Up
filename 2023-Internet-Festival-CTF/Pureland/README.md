# Attachment

[tarball](pureland.zip)

# Solution

- There is one OOB when summarizing items
- We have 8 bytes overflow to overwrite the length of the arrary
- ROP to get the shell
- Tip: Use write to fill the stdout buffer so we can read the leaked data/flag

# Exploit

[exp.py](exp.py)
