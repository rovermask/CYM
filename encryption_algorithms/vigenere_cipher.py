def vigenere_encrypt(plain_text, key):
    """Vigenere cipher encryption."""
    key = key.upper()
    result = ""
    key_index = 0
    for char in plain_text:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            if char.isupper():
                result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            key_index += 1
        else:
            result += char
    return result


def vigenere_decrypt(cipher_text, key):
    """Vigenere cipher decryption."""
    key = key.upper()
    result = ""
    key_index = 0
    for char in cipher_text:
        if char.isalpha():
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - ord('A')
            if char.isupper():
                result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            key_index += 1
        else:
            result += char
    return result


if __name__ == "__main__":
    print(vigenere_encrypt("ATTACKATDAWN", "LEMON"))
    print(vigenere_decrypt("LXFOPVEFRNHR", "LEMON"))