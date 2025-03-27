---
title: "Dragon Flight – Dynamic Subarray Sum Queries (HTB Cyber Apocalypse 2025)"
tags: [CTF, python, kadane, segment updates, coding]
---

# Dragon Flight 🐉🛫

![Python](https://img.shields.io/badge/language-Python-blue.svg)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue.svg)
![Category](https://img.shields.io/badge/category-Coding-lightgrey.svg)
![CTF](https://img.shields.io/badge/Event-HTB%20Cyber%20Apocalypse%202025-purple)

In the mystical realm of the Floating Isles, dragons soar between ancient sanctuaries. 

However, unpredictable wind conditions can either boost or hinder their journeys.

## 📚 Table of Contents

- [Challenge Description 📜](#challenge-description-)
- [Flight Example ✈️](#flight-example-%EF%B8%8F)
- [Solution Strategy 🧠](#solution-strategy-)
- [Code 🧪](#code-)
- [Notes 📋](#notes-)
- [Conclusion 🧾](#conclusion-)

## Challenge Description 📜

In the mystical realm of the Floating Isles, ancient dragons traverse the skies between floating sanctuaries.  

However, unpredictable winds now pose a dynamic threat! 🌬️

As the Dragon Flight Master, your task is to handle:
- Real-time wind changes,
- Flight path queries to find the **maximum safe distance** dragons can cover.

This challenge requires implementing **dynamic updates and range queries** on an array — specifically, maximum contiguous subarray sums (Kadane’s Algorithm style).

**Input Format:**
1. First Line: Two integers `N` and `Q`  
   - `N` = number of flight segments  
   - `Q` = number of operations
2. Second Line: List of `N` integers (initial wind effects per segment)  
   - Positive = tailwind (boost)  
   - Negative = headwind (drag)
3. Next `Q` lines:
   - Update: `U i x` → set the `i`th segment to value `x`
   - Query: `Q l r` → get the **maximum contiguous sum** in range `[l, r]` (1-indexed)

## Flight Example ✈️

### Input:
```
6 6
-10 -7 -1 -4 0 -5
Q 3 3
U 2 9
Q 6 6
U 1 -1
Q 6 6
U 5 -9
```

### Output:
```
-1
-5
-5
```

Each query asks for the best continuous flight segment in a range — considering both favorable and unfavorable winds.

## Solution Strategy 🧠

We use a **simple version of Kadane's Algorithm** for each query:
- For every `Q l r` operation:
  - Slice the subarray from `l-1` to `r`
  - Apply Kadane to get the **max subarray sum**

Updates (`U i x`) are handled directly by modifying the list in place.

This is not the most optimized (e.g., no segment tree), but it fits perfectly for a small number of operations.

## Code 🧪

```python
def kadane(arr):
    max_current = max_global = arr[0]
    for x in arr[1:]:
        max_current = max(x, max_current + x)
        max_global = max(max_global, max_current)
    return max_global

# Read N and Q
nq = input().strip()
n, q = map(int, nq.split())

# Read wind segment array
arr = list(map(int, input().strip().split()))

# Process each operation
for _ in range(q):
    op = input().strip().split()
    if op[0] == 'U':
        i = int(op[1]) - 1
        x = int(op[2])
        arr[i] = x
    elif op[0] == 'Q':
        l = int(op[1]) - 1
        r = int(op[2])
        sub = arr[l:r]
        print(kadane(sub))
```

## Notes 📋

- This uses Kadane’s Algorithm for each query: `O(n)` per query.
- Input is assumed to be trusted and well-formed.
- For larger datasets, a **segment tree** would improve performance, but isn’t needed here.

## Conclusion 🧾

This challenge combines dynamic array updates with maximum subarray logic — a great exercise in balancing real-time changes with analytical queries.

🧠 Key takeaways:
- Kadane’s is simple but powerful.
- Always watch for zero vs one-based indexing.
- Algorithms matter — but so does reading the input format carefully.

Now guide those dragons through the safest skies! 🐉🌬️

🔙 [Back to Cyber Apocalypse 2025 Writeups](../../)
