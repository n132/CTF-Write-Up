# Attachment

[Attachment](boogie-woogie.tar)

# Solution

Solved it with @zolutal! 

Spent very 15 hours because of the IO issues and the server setting, it’s not hard but helped me review a lot of of old stuff. Also, I learned more interesting skills for `one_gadget` :

1. Install the latest version can provide more (even if most of them are strict)
2. Use `-L`  to give more interesting gadgets

Solution:

- The heap randomization is limited (https://github.com/n132/BeapOverflow) so we can brute force it (even Dice Gang added a 1-sec PoW).
- Swap a PIE address into data to leak PIE
- Guess a Heap address (1/8292)
- Create an unsorted bin by House-of-Orange
- Leak Libc base
- Leak Ld Base
- Fix the `rbp`  on stack to make it possible to attack with `RBP`-related `one_gadget`

By the way, I scan the writeable memory space and create a map so we can pick up some values and swap them to the target address. My exploit script is verbose and ugly but I don’t have time to fix it.

# Exploit

[exp.py](exp.py)
