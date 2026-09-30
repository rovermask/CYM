"""
RSA Encryption — Educational Implementation
NOTE: This is a simplified RSA for demonstration purposes only.
      Real RSA uses OAEP padding and much larger primes.
"""


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    """Extended Euclidean Algorithm to find modular inverse."""
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % phi


def rsa_generate_keys():
    """Generate RSA public and private keys using small demo primes."""
    p, q = 53, 59
    n = p * q          # 3127
    phi = (p - 1) * (q - 1)   # 3016

    # Find e coprime to phi
    e = 3
    while gcd(e, phi) != 1:
        e += 2

    # Compute private exponent d
    d = mod_inverse(e, phi)

    return (e, n), (d, n)


def rsa_encrypt_char(char_code, e, n):
    """Encrypt a single integer value."""
    return pow(char_code, e, n)


def rsa_decrypt_char(cipher_val, d, n):
    """Decrypt a single integer value."""
    return pow(cipher_val, d, n)


def rsa_algo(message):
    """Encrypt a message character by character using RSA demo keys."""
    public_key, private_key = rsa_generate_keys()
    e, n = public_key

    encrypted = []
    for char in message:
        code = ord(char)
        if code >= n:
            raise ValueError(
                f"Character {char!r} (code {code}) is outside the range this demo RSA can encrypt "
                f"(codes below {n})."
            )
        encrypted.append(str(rsa_encrypt_char(code, e, n)))

    return ' '.join(encrypted)


def rsa_decrypt_message(cipher_values, d, n):
    """Decrypt a space-separated string of cipher values."""
    values = [int(v) for v in cipher_values.split()]
    decrypted = ''.join(chr(rsa_decrypt_char(v, d, n)) for v in values)
    return decrypted


if __name__ == "__main__":
    pub, priv = rsa_generate_keys()
    print(f"Public key  (e, n): {pub}")
    print(f"Private key (d, n): {priv}")

    message = "Hi"
    encrypted = rsa_algo(message)
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {rsa_decrypt_message(encrypted, priv[0], priv[1])}")