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
