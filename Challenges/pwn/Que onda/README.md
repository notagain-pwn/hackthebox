---
title: "Que onda ⁉️ - Pwn Easy Challenge Writeup"
tags: [HTB, pwn, easy, reverse, stack]
---

# Que onda ⁉️

![Category](https://img.shields.io/badge/category-Pwn-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![HTB](https://img.shields.io/badge/HTB-Challenge-green)

> Que onda! Welcome to the festival of Pwn! This is a small guide to help you continue your journey, follow the instructions in README.txt

"Hola mi Amigos! Send me the string 'flag' and I will give you uno grande prize!!"

This one is as straightforward as it sounds — and we love that.

## 📚 Table of Contents

- [Binary Overview 🧩](#binary-overview-)
- [Reverse Engineering 🔍](#reverse-engineering-)
- [The Check 🔐](#the-check-)
- [The Exploit 💥](#the-exploit-)
- [Result ✅](#result-)
- [Conclusion 🧾](#conclusion-)

## Binary Overview 🧩

We’re given a simple 64-bit ELF binary. Upon execution, it prints a message and awaits input.

Protections:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      Enabled
```

Nothing crazy here, just the basics.

## Reverse Engineering 🔍

The binary calls `banner()` right away. Inside it, we see:

```c
read(0, &local_28, 6);
strncmp((char *)&local_28, "flag", 4);
if (iVar1 == 0) {
    read_flag();
}
```

![Banner Ghidra](https://github.com/user-attachments/assets/75ed0d92-8f4d-4ae0-9389-1472d6f7693f)

- It reads 6 bytes from stdin
- Then compares the first 4 bytes with `"flag"`

If they match, we get the flag.

## The Check 🔐

We only need to satisfy this:
```
strncmp(input, "flag", 4) == 0
```

So sending `"flag"` (optionally with newline) is enough.

## The Exploit 💥

```
echo flag | ./que_onda
```

Or with Python:
```python
#!/usr/bin/env python3
from pwn import *
import argparse

def build_payload():
    return b"flag\n"

def run_local(binary_path):
    p = process(binary_path)
    p.send(build_payload())
    return p.recvall().decode()

def run_remote(ip, port):
    p = remote(ip, int(port))
    p.send(build_payload())
    return p.recvall().decode()

def main():
    parser = argparse.ArgumentParser(description="Exploit for Que onda challenge (HTB)")
    parser.add_argument("--remote", action="store_true", help="Run against remote target")
    parser.add_argument("--ip", help="Remote IP address")
    parser.add_argument("--port", help="Remote port")
    parser.add_argument("--binary", default="./que_onda", help="Local binary path (default: ./que_onda)")
    args = parser.parse_args()

    if args.remote:
        if not args.ip or not args.port:
            print("[!] You must provide both --ip and --port in remote mode.")
            return
        result = run_remote(args.ip, args.port)
    else:
        result = run_local(args.binary)

    print("[+] Response from target:\n")
    print(result)

if __name__ == "__main__":
    main()
```

## Result ✅

![Flag](https://github.com/user-attachments/assets/7ac00653-8717-478e-8de7-2bfa134dbe15)

```
$ HTB{w3lc0m3_2_htb00_pwn_f35t1v4l}
```

## Conclusion 🧾

A fun introductory challenge. This one is not about exploitation, but verifying your ability to:

- Reverse statically
- Identify program flow
- Trigger conditional behavior

Sometimes the shortest path **is** the intended path 😎

🔙 [Back to Challenge Writeups](../../)
