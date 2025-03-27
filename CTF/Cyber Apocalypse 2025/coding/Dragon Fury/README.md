---
title: "Dragon Fury – Unique Sum from Subarrays (HTB Cyber Apocalypse 2025)"
tags: [CTF, python, backtracking, coding]
---

# Dragon Fury 🐉🔥

![Python](https://img.shields.io/badge/language-Python-blue.svg)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue.svg)
![Category](https://img.shields.io/badge/category-Coding-lightgrey.svg)
![CTF](https://img.shields.io/badge/Event-HTB%20Cyber%20Apocalypse%202025-purple)

In the final confrontation, the dragons unleash their fury against Malakar’s forces. 

Simulate the battle by computing the total damage dealt over successive rounds until victory is achieved.

---

## 📚 Table of Contents

- [Challenge Description 📜](#challenge-description-)
- [Example 🔍](#example-)
- [Solution Strategy 🧠](#solution-strategy-)
- [Code 🧪](#code-)
- [Notes 📋](#notes-)
- [Conclusion 🧾](#conclusion-)

---

## Challenge Description 📜

In the epic battle against Malakar's dark forces, the ancient dragons must unleash a series of precise attacks.  

Each attack round offers several potential damage values—but only one combination of attacks will **sum up exactly** to the damage required to vanquish the enemy.

Can you guide the dragons to unleash the perfect fury?

**Input:**
- A string representing a list of subarrays. Each subarray contains integers — possible damage values for that round.
- A single integer representing the **target damage**.

Example:
```
[[13, 15, 27, 17], [24, 15, 28, 6, 15, 16], [7, 25, 10, 14, 11], [23, 30, 14, 10]]
77
```

**Output:**
- A single list of integers: one value selected from each subarray, whose sum equals the target damage.

## Example 🔍

### Input:
```
[[13, 15, 27, 17], [24, 15, 28, 6, 15, 16], [7, 25, 10, 14, 11], [23, 30, 14, 10]]
77
```

### Output:
```
[13, 24, 10, 30]
```

Each number is selected from a different round, and their total is exactly `77`.

## Solution Strategy 🧠

We approach this using **backtracking**:
- At each round (subarray), we try all damage values.
- We keep track of the current sum and current combination.
- If the current sum exceeds the target, we skip.
- Once we reach the final round, we check if the total matches the target.

Because the challenge **guarantees exactly one solution**, we don’t need advanced pruning or memoization.

## Code 🧪

```python
def find_combination(rounds, target):
    result = []

    def backtrack(index, current_combo, current_sum):
        if index == len(rounds):
            if current_sum == target:
                result.extend(current_combo)
            return

        for dmg in rounds[index]:
            if current_sum + dmg <= target:
                backtrack(index + 1, current_combo + [dmg], current_sum + dmg)

    backtrack(0, [], 0)
    return result


# 🧾 Input: one line for the damage matrix, one for the target
input_text = input().strip()
target = int(input().strip())
damage_rounds = eval(input_text)

# 🐉 Find the attack combo!
solution = find_combination(damage_rounds, target)
print(solution)
```

## Notes 📋

- Assumes the input is a valid list of lists + integer.
- Uses simple recursive backtracking, no libraries or imports needed.
- Guaranteed to find the unique valid combo thanks to the problem constraints.

## Conclusion 🧾

The ancient dragons won’t act without precision.  

This challenge is a clean test of your ability to guide a recursive path to the **exact sum**, under strict constraints.

🧠 Takeaway: Backtracking is your friend when brute-force needs to be smart.

And always remember:
> With the right sequence, even dragons obey. 🐉✨

🔙 [Back to Cyber Apocalypse 2025 Writeups](../../)
