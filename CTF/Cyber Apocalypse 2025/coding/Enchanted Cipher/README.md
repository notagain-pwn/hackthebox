---
title: "Enchanted Cipher – Enhanced Caesar shift (HTB Cyber Apocalypse 2025)"
tags: [CTF, python, enhanced caesar shift, coding]
---

# Locked Book – Enchanted Cipher 🔐

![Python](https://img.shields.io/badge/language-Python-blue.svg)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue.svg)
![Category](https://img.shields.io/badge/category-Coding-lightgrey.svg)
![CTF](https://img.shields.io/badge/Event-HTB%20Cyber%20Apocalypse%202025-purple)

A mysterious cipher has corrupted historical records in the Grand Arcane Codex. 

Each entry has been encrypted using an *Enchanted Shifting Cipher*, and our goal is to **restore the original plaintext** made up of 3–7 randomly generated words.

## Challenge Description 📜

### Cipher Rules:

1. **Alphabetical characters are grouped in chunks of 5**. Non-alphabetical characters are ignored when forming groups, but **retained in their original position** in the final output.
2. Each group of 5 characters is shifted using a **random Caesar shift between 1 and 25**.
3. The **same shift is applied to all characters within a group**.
4. After the ciphertext, two more lines are provided:
   - The number of shift groups.
   - A list of shift values (integers between 1 and 25), one for each group, in order.

## 🏛️ What is a Caesar Cipher?

The **Caesar cipher** is one of the oldest and simplest encryption techniques. Named after Julius Caesar (who reportedly used it to protect military messages), it works by shifting each letter in the plaintext by a fixed number of positions in the alphabet.

For example, with a shift of 3:
- `a` → `d`
- `b` → `e`
- `c` → `f`
- and so on...

It wraps around at the end, so:
- `x` → `a`
- `y` → `b`
- `z` → `c`

👉 It’s easy to implement, easy to break — but still a fun starting point for exploring classical ciphers!

In this challenge, the Caesar cipher is enhanced with random shifts and grouping, making it slightly trickier than the original.

## Example 🔍

**Input:**
```
ibeqtsl
2
[4, 7]
```

**Output:**
```
example
```

**Explanation:**

- The encrypted text `"ibeqtsl"` contains 7 letters.
- It’s split into 2 groups:  
  - Group 1: `"ibeqt"` → shift -4 → `"examp"`  
  - Group 2: `"sl"` → shift -7 → `"le"`  
- Result: `"example"`

## Solution 🤩

We implement a simple parser and decryption function in Python that:

1. Iterates through the input string.
2. Ignores non-alphabetical characters for grouping.
3. Applies the appropriate Caesar shift (in reverse) for each group.
4. Reconstructs and returns the decrypted string, preserving any non-alphabetic characters.

## Code 🦖

```python
def decrypt_cipher(text, group_count, shifts):
    decrypted = ''
    alpha_index = 0  # Tracks alphabetical characters for grouping

    for char in text:
        if char.isalpha():
            group_num = alpha_index // 5
            shift = shifts[group_num]
            decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            decrypted += decrypted_char
            alpha_index += 1
        else:
            decrypted += char

    return decrypted


input_text = input().strip()
group_count = int(input().strip())
shift_values = eval(input().strip())

decoded = decrypt_cipher(input_text, group_count, shift_values)
print(decoded)
```

## Notes 📋

- Assumes all input characters are lowercase.
- Designed to be easily adaptable to handle uppercase letters or punctuation if needed.
- Can be reused as a helper tool for similar grouped cipher patterns.

## Files 📁

- `solution.py` – Python script with decryption logic.
- `README.md` – This documentation.

## Sample Test ✅

**Input:**
```
pdobgjvyn
2
[3, 10]
```

**Output:**
```
magickey
```
## Conclusion 🧾

A classic Caesar cipher? Not quite. 🧙‍♂️
This one came enchanted with just enough magic (aka random shifts and grouping tricks) to throw off a hasty decoder.

Nothing too deep technically, but a great reminder that even the most basic crypto can turn sneaky with the right twist. Perfect as an intro-level coding puzzle or a warm-up before diving into heavier crypto.

**Lesson learned?** Always read the rules twice, and never trust a wizard with a cipher. 🔥
