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
