---
title: "The Clockwork Guardian – Shortest Path Avoiding Enemies (HTB Cyber Apocalypse 2025)"
tags: [CTF, python, BFS, grid pathfinding, coding]
---

# The Clockwork Guardian ⏰🛡️

![Python](https://img.shields.io/badge/language-Python-blue.svg)
![Difficulty](https://img.shields.io/badge/difficulty-Easy-blue.svg)
![Category](https://img.shields.io/badge/category-Coding-lightgrey.svg)
![CTF](https://img.shields.io/badge/Event-HTB%20Cyber%20Apocalypse%202025-purple)

The Clockwork Sentinels defending Eldoria’s Skywatch Spire have gone rogue! 

You must navigate the spire, avoiding hostile sentinels and finding the safest path.

## 📚 Table of Contents

- [Challenge Description 📜](#challenge-description-)
- [Example Grid 🔍](#example-grid-)
- [Solution Strategy ⚙️](#solution-strategy-%EF%B8%8F)
- [Code 🧪](#code-)
- [Notes 📋](#notes-)
- [Conclusion 🧾](#conclusion-)

## Challenge Description 📜

The Clockwork Sentinels defending Eldoria's Skywatch Spire have gone rogue!  

Your task is to find the **shortest safe path** through the spire, avoiding hostile sentinels and reaching the exit marked `'E'`.

This challenge is about **grid-based pathfinding** using **Breadth-First Search (BFS)** — a classic algorithmic puzzle with a fantasy twist. 🧭

**Input:**
- A grid (2D list) where:
  - `0` = safe tile
  - `1` = enemy sentinel (obstacle)
  - `'E'` = exit
- You always start at `(0, 0)`.

Your mission: Find the **shortest path** to the `'E'`, avoiding all `1`s.

## Example Grid 🔍

### Input:
```python
[
    [0, 0, 1, 0, 0, 1],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 1, 1, 0, 'E']
]
```

### Output:
```
8
```

The optimal path from `(0,0)` to the exit (`'E'`) is exactly 8 steps.

## Solution Strategy ⚙️

This is a **shortest path in a grid** problem — perfect for **Breadth-First Search (BFS)**.

BFS is ideal because it explores all positions at the current "depth" (number of steps) before going deeper.

**Steps:**
1. Start from `(0, 0)` with `steps = 0`.
2. At each tile, explore all 4 directions (up, down, left, right).
3. Avoid revisiting tiles or stepping on sentinels (`1`).
4. Stop when the exit `'E'` is found — return `steps`.

## Code 🧪

```python
from collections import deque

def shortest_safe_path(grid):
    rows, cols = len(grid), len(grid[0])
    visited = [[False]*cols for _ in range(rows)]
    directions = [(-1,0), (1,0), (0,-1), (0,1)]

    queue = deque([(0, 0, 0)])  # (x, y, steps)
    visited[0][0] = True

    while queue:
        x, y, steps = queue.popleft()
        if grid[x][y] == 'E':
            return steps

        for dx, dy in directions:
            nx, ny = x+dx, y+dy
            if 0 <= nx < rows and 0 <= ny < cols:
                if not visited[nx][ny] and grid[nx][ny] != 1:
                    visited[nx][ny] = True
                    queue.append((nx, ny, steps+1))
    return -1  # No path found

# Input parsing
input_text = input()
grids = eval("[" + input_text + "]")  # Caution: assumes trusted input

# Solve all given grids
results = []
for grid in grids:
    steps = shortest_safe_path(grid)
    results.append(steps)

# Output results
for res in results:
    print(f"{res}")
```

## Notes 📋

- This uses **BFS**, ensuring the shortest path in unweighted grids.
- Assumes the grid is well-formed and there's a valid path to `'E'`.
- Can be extended to track the actual path or handle multiple starts/exits.

## Conclusion 🧾

The Clockwork Guardian tests your grid traversal and pathfinding fundamentals.  

It's a clean, classic BFS application dressed in fantasy coding armor. 🛡️✨

🧠 Key takeaways:
- BFS is ideal for shortest path problems with uniform cost.
- Think in terms of **layers of expansion** — like a growing ring around the start point.
- Grid traversal = one of the most transferable skills in algo/CTF/puzzle solving.

Now go forth and deactivate those rogue sentinels. ⚙️

🔙 [Back to Cyber Apocalypse 2025 Writeups](../../)
