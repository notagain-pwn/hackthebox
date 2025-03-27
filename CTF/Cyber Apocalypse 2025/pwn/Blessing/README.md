---
title: "Blessing 🙏✨ – Logic Bug Exploit via Failed malloc (HTB Cyber Apocalypse 2025)"
tags: [CTF, binary exploitation, logic bug, write-what-where, pwn]
---

# Blessing 🙏✨

![pwntools](https://img.shields.io/badge/pwntools-✔️-brightgreen)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Category](https://img.shields.io/badge/category-Pwn-orange)
![CTF](https://img.shields.io/badge/Event-HTB%20Cyber%20Apocalypse%202025-purple)

In the realm of Eldoria, where warriors roam, The Dragon's Heart they seek, from bytes to byte's home.  

Through exploits and tricks, they boldly dare, To conquer Eldoria, with skill and flair.

## 📚 Table of Contents

- [Initial Inspection 🕵️](#initial-inspection-)
- [Key observation 🔍](#key-observation-)
- [Vulnerability 🧠](#vulnerability-)
- [The Revelation 💡](#the-revelation-)
- [Exploit 🎯](#exploit-)
- [Conclusion 🧠](#conclusion-)

## Initial Inspection 🕵️ 

Let’s begin by checking the binary protections:

![checksec output](https://github.com/user-attachments/assets/7fb9eb67-543f-458d-a06c-f1bfeb03eaf8)

Then we dive into Ghidra:

![Ghidra](https://github.com/user-attachments/assets/d88da6e0-f317-4df6-a742-15fe72d10433)

### Key observation 🔍 

- `local_20` is initialized with a large `malloc(0x30000)` — this means it's **mmaped**, not on the regular heap.
- A `1` is written at the start of the mmaped chunk.
- The binary **leaks** the address of this mmaped region.
- The condition to win the challenge is: **erase that `1` and replace it with a `0`**.

After that, the binary:
- Asks for a “song size” → `malloc` with user input.
- Asks for the song content.

But here's the trick — the actual song content doesn’t matter.

## Vulnerability 🧠 

What matters is this line in the code:

```
*(undefined8 *)((long)local_18 + (local_30 - 1)) = 0;
```
### Breakdown:
    
- `local_18` = pointer returned by malloc
- `local_30` = user-supplied length
- The binary writes a `0` at: `local_18 + local_30 - 1`

At first, I thought: *"I just need to malloc a large chunk that gets mmaped and place it just before `local_20` to overwrite its first byte."*

I tried that approach for a while… but never managed to get closer than ~24 bytes. Turns out, due to how **mmap vs heap allocations, page alignment,** and general memory layout work, **that strategy wasn’t feasible.**

I then looked for other things I could overwrite — either in the heap or mmap area — but nothing useful surfaced.

Honestly, I was stuck for a while... until I had a small epiphany:

## The Revelation 💡 

Then it hit me. What if I asked for a **huge, invalid allocation**, like `0xFFFFFFFF`?

- `malloc()` fails
- `local_18` == NULL
- `local_30` == `0xFFFFFFFF`
- The binary attempts to write a `0` at: `NULL + 0xFFFFFFFF - 1 = 0xFFFFFFFE`

Now, **if we set the malloc size to be equal to the leaked address + 1**, then:

- `malloc(leak + 1)` fails
- `local_18 == 0`
- `local_30 == leak + 1`
- Write occurs at: `0 + leak + 1 - 1 = leak` → boom 💥

We overwrite the `1` at the beginning of the mmaped chunk with a `0` and trigger the win.

## Exploit 🎯

Here's the minimal working exploit:

```
from pwn import *

io = process("./vuln")

io.recvuntil(b"accept this: ")
leak = int(io.recv(14), 16)

# Send length = leak + 1 to land the write at the leak address
io.sendlineafter(b"length:", str(leak + 1).encode())
io.sendafter(b"song:", b"0")  # content doesn't matter

print(io.recvall())
```
(More polished exploit here: [exploit.py](https://github.com/notagain-pwn/hackthebox/blob/main/CTF/Cyber%20Apocalypse%202025/pwn/Blessing/exploit.py))

![Challenge solved - flag output](https://github.com/user-attachments/assets/6f37ba71-2977-45fe-b51f-01f7aee406d3)

Pwned! 🙏✨

## Conclusion 🧠

This challenge looked deceptively simple, but it required understanding:

- The difference between malloc and mmap allocations
- What happens when malloc fails
- Subtle memory arithmetic (NULL + user-controlled offset)
- A clean "write-what-where" scenario without any classic overflow

Sometimes, all it takes is one invalid malloc() to take down a dragon. 🐉✨

🔙 [Back to Cyber Apocalypse 2025 Writeups](../../)
