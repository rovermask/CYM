import math
import random
from string import ascii_letters
alphabets = {i: ord(i) for i in ascii_letters}

def gcd(a, h):
	temp = 0
	while(1):
		temp = a % h
		if (temp == 0):
			return h
		a = h
		h = temp

def rsa_encrypt(message):
    p = 53
    q = 59
    n = p*q
    e = random.randrange(1,9)
    phi = (p-1)*(q-1)
    while (e < phi):
        if(gcd(e, phi) == 1):
            break
        else:
            e = e+1
    plain_text=""
    for i in message:
        if(i.isupper()):
            plain_text+=str(ord(i)-64)
        else:
            plain_text+=str(ord(i)-96)
    plain_text=int(plain_text)

    c = pow(plain_text, e)
    c = math.fmod(c, n)
    return c

def rsa_decrypt():
    pass

if __name__=="__main__":
    pass