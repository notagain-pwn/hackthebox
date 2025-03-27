---
title: "Impossimaze – Terminal Rendering Reversing Challenge (HTB Cyber Apocalypse 2025)"
tags: [CTF, reversing, ncurses, terminal size, debugging, display logic]
---

# Impossimaze 🎭

![Language](https://img.shields.io/badge/language-Reversing-green.svg)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue.svg)
![Category](https://img.shields.io/badge/category-Reversing-purple.svg)
![CTF](https://img.shields.io/badge/Event-HTB%20Cyber%20Apocalypse%202025-purple)

## 📚 Table of Contents

- [Challenge Overview 🧠](#challenge-overview-)
- [Initial Analysis 🔍](#initial-analysis-)
- [The Hidden Check 🧩](#the-hidden-check-)
- [Getting the Flag 🖥️](#getting-the-flag-%EF%B8%8F)
- [Conclusion 🧾](#conclusion-)

## Challenge Overview 🧠

Elowen has been cursed to roam forever in an inescapable maze. 

You need to break her curse and set her free.

## Initial Analysis 🔍

The binary opens a terminal interface rendering a visual maze with `ncurses`. There was no clear way to extract the flag through standard gameplay. However, something felt... off.

Running the binary simply displays a large maze of characters. It seemed dynamic and didn’t print any flag, even after wandering or interacting.

Loading the binary into Ghidra, the main function (named `FUN_00101283`) contains calls like `initscr`, `cbreak`, `noecho`, `curs_set`, and `keypad`, confirming the use of `ncurses`.

### What the binary does 🧱

- Initializes ncurses
- Gets terminal size: `getmaxy()` and `getmaxx()`
- Draws a maze using characters (`A`, `V`, `|`, etc.) generated from a helper function `FUN_00101249(x, y)`
- Places the cursor (`X`) in the center of the screen
- Waits for arrow key inputs to move
- Displays the dimensions at the top-left (`13:37`, for example)

## The Hidden Check 🧩

Here’s the key check inside the binary:

```c
if ((uVar3 == 0xd) && (uVar4 == 0x25)) {
    // draw hidden content
}
```

Which means:
- Height = 0xD = 13 (in decimal)
- Width  = 0x25 = 37 (in decimal)

If and only if the terminal size is **13x37**, an additional block of code runs!

This code reads from a memory region `DAT_001040c0`, maps it using a lookup array at `DAT_00104120`, and prints the result character by character at line 6.

In short, if the terminal is resized to **13 rows by 37 columns**, the flag will appear!

## Getting the Flag 🖥️

I resized my terminal to exactly `13x37` using `tilix` in my case. 

Sure enough, the maze updated and the flag was revealed!

![Flag Screenshot](https://github.com/user-attachments/assets/2bfdff47-1d74-4bb7-a402-419c09d71105)

```
HTB{th3_curs3_is_brok3n}
```

## Conclusion 🧾

This challenge combined binary reversing with visual analysis. By carefully understanding the ncurses logic, we revealed hidden behavior triggered by specific terminal dimensions.

- `ncurses`-based UIs can contain hidden logic based on dimensions or key events.
- Reverse engineering binaries with graphical elements can reveal clever tricks.
- Sometimes, the “game” is not in the gameplay, but in the **code itself**.

### Lessons Learned 📘

- Don't trust what you *see* — sometimes display logic hides secrets.
- Reverse engineering graphical binaries can reveal creative tricks.
- Always inspect conditions involving UI elements like dimensions or user input.

🔙 [Back to Cyber Apocalypse 2025 Writeups](../../)
