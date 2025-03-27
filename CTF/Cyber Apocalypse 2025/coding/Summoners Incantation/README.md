---
title: "Summoners Incantation – Max Non-Adjacent Sum (HTB Cyber Apocalypse 2025)"
tags: [CTF, python, dynamic programming, coding]
---

# Summoners Incantation 🔮

![Python](https://img.shields.io/badge/language-Python-blue.svg)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue.svg)
![Category](https://img.shields.io/badge/category-Coding-lightgrey.svg)
![CTF](https://img.shields.io/badge/Event-HTB%20Cyber%20Apocalypse%202025-purple)

To awaken the ancient power of the Dragon's Heart, the summoners must combine magical incantation tokens. 

However, the tokens are delicate; no two adjacent tokens can be combined without losing their energy. The optimal incantation is the maximum sum obtainable by choosing non-adjacent tokens.

## 📚 Table of Contents

- [Challenge Description 📜](#challenge-description-)
- [Example 🔍](#example-)
- [Solution Strategy 🤯](#solution-strategy-)
- [Code 🧪](#code-)
- [Notes 📋](#notes-)
- [Conclusion 🧾](#conclusion-)

## Challenge Description 📜

Deep within the ancient halls lies the secret of the Dragon's Heart—a power that can only be unlocked by combining magical tokens in just the right way.  

But beware: if you combine two adjacent tokens, their energy is lost forever to the void.

Your task is to determine the **maximum amount of energy** that can be harnessed by selecting tokens such that **no two selected tokens are adjacent**.

This challenge maps to a classic dynamic programming problem: **the Maximum Sum of Non-Adjacent Elements**.

**Input:**
- A single line containing a Python-style list of integers.
  Example: `[3, 2, 5, 10, 7]`

**Output:**
- A single integer: the maximum energy you can collect, **without picking adjacent elements**.

**Rule:** If you select two adjacent tokens, their energy is neutralized — so only non-adjacent selections are valid.

## Example 🔍

### Input 1:
```
[3, 2, 5, 10, 7]
```

**Optimal selection**: 3, 5, and 7 → Total: `3 + 5 + 7 = 15`

### Input 2:
```
[10, 18, 4, 7]
```

**Optimal selection**: 18 and 7 → Total: `18 + 7 = 25`

## Solution Strategy 🤯

This is a textbook **dynamic programming** scenario.

Let’s break it down:

- At each position `i`, you have **two options**:
  1. **Include** the current token → you can't include the previous one.
  2. **Exclude** the current token → take the best of previous include/exclude.

We track two values:
- `incl` → max energy including the current token
- `excl` → max energy excluding the current token

Update logic:
```python
new_excl = max(incl, excl)
incl = excl + current_energy
excl = new_excl
```

Final answer = `max(incl, excl)`

## Code 🧪

```python
# Read the list of token energies as a string, e.g. "[3, 2, 5, 10, 7]"
input_text = input().strip()
tokens = eval(input_text)

# Initialization
incl = 0  # Max energy including current token
excl = 0  # Max energy excluding current token

# Dynamic programming loop
for energy in tokens:
    new_excl = max(incl, excl)
    incl = excl + energy
    excl = new_excl

# Final answer: best of including or excluding last token
print(max(incl, excl))
```

## Notes 📋

- Input must be a **valid Python list** (as string).
- This algorithm runs in **O(n)** time and uses **O(1)** space — very efficient!
- Can easily be extended to return the **actual list of chosen tokens** if needed.
- Commonly referred to as the "House Robber Problem" in Leetcode/Algo circles.

## Conclusion 🧾

The Summoner’s Incantation is a clever twist on a fundamental programming concept.

🧠 Key takeaways:
- Use dynamic programming when a problem has **optimal substructure + overlapping subproblems**.
- Track “include” and “exclude” states when adjacency is restricted.
- You don't always need recursion — simple state variables often do the trick!

And remember:
> When facing magic, plan like a wizard. 🔮✨

🔙 [Back to Cyber Apocalypse 2025 Writeups](../../)
