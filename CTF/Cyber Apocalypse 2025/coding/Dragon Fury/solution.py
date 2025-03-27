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

