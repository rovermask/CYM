"""Caesar cipher — shifts ASCII letters, leaves everything else untouched."""


def caesar_cipher(plain_text, key):
    """Encrypt `plain_text` by shifting each ASCII letter `key` places forward."""
    result = []
    for ch in plain_text:
        if 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - 65 + key) % 26 + 65))
        elif 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - 97 + key) % 26 + 97))
        else:
            result.append(ch)
    return ''.join(result)


def caesar_decrypt(cipher_text, key):
    return caesar_cipher(cipher_text, -key)


if __name__ == "__main__":
    print(caesar_cipher("Vibhum", 5))
