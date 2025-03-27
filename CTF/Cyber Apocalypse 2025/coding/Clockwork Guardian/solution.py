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
