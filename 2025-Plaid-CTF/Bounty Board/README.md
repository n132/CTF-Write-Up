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
Success Rate 1/(1<<12)
```py
TODO.
```

