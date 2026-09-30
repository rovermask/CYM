"""Swapping cipher — vowels map onto reversed vowels, consonants onto reversed consonants."""
from string import ascii_uppercase

_VOWELS = "AEIOU"
_CONSONANTS = "".join(c for c in ascii_uppercase if c not in _VOWELS)

_MAP = {}
for _group in (_VOWELS, _CONSONANTS):
    for _a, _b in zip(_group, reversed(_group)):
        _MAP[_a] = _b
        _MAP[_a.lower()] = _b.lower()


def swapping_encrypt(text):
    """Letters are swapped (case preserved); any other character is left as-is.

    The mapping is an involution, so the same function also decrypts.
    """
    return "".join(_MAP.get(ch, ch) for ch in text)


swapping_decrypt = swapping_encrypt


if __name__ == "__main__":
    print(swapping_encrypt("Hello, World 123"))
