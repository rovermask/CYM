def atbash_cipher(text):
    """
    Atbash cipher: reverses the alphabet.
    A->Z, B->Y, C->X ... Z->A (symmetric — same function encrypts and decrypts)
    """
    result = ""
    for char in text:
        if char.isupper():
            result += chr(ord('Z') - (ord(char) - ord('A')))
        elif char.islower():
            result += chr(ord('z') - (ord(char) - ord('a')))
        else:
            result += char
    return result


def rot13(text):
    """ROT13 — special case of Caesar cipher with shift 13 (self-inverse)."""
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + 13) % 26 + base)
        else:
            result += char
    return result


if __name__ == "__main__":
    print(atbash_cipher("HELLO"))   # SVOOL
    print(atbash_cipher("SVOOL"))   # HELLO  (self-inverse)
    print(rot13("Hello, World!"))   # Uryyb, Jbeyq!