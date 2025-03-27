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
