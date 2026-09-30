def atbash_cipher(text):
    """
    Atbash cipher: reverses the alphabet.
    A->Z, B->Y, C->X ... Z->A (symmetric — same function encrypts and decrypts)
    """
    result = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        elif 'a' <= ch <= 'z':
            result.append(chr(ord('z') - (ord(ch) - ord('a'))))
        else:
            result.append(ch)
    return ''.join(result)


def rot13(text):
    """ROT13 — special case of Caesar cipher with shift 13 (self-inverse)."""
    result = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        elif 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        else:
            result.append(ch)
    return ''.join(result)


if __name__ == "__main__":
    print(atbash_cipher("HELLO"))   # SVOOL
    print(atbash_cipher("SVOOL"))   # HELLO  (self-inverse)
    print(rot13("Hello, World!"))   # Uryyb, Jbeyq!
