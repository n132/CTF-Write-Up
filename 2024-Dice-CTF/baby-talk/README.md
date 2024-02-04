# Attachment

[Attachment](baby-talk.tar)

# Solution

The vulnerability is the program didn’t append a guard byte after user input so the attackers could operate the header of the next heap chunk, which means this is an off-by-null challenge. We are quite free to malloc and free so let’s shrink to create overlap and get a shell by hijacking hooks.


# Exploit

[exp.py](exp.py)
