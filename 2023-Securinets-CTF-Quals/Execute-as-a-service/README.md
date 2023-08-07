# Attachment

[zip](Execute-as-a-service.zip)

# Solution

Attack Buffer Overflow with C Code.

# Exploit

[exp.py](exp.py)

[exp.c](exp.c)

`musl-gcc ./exp.c -o ./exp -w --static && cat ./exp | base64 > exp_enc && python3 ./exp.py`