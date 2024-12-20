from string import ascii_uppercase
alphabets=[i for i in ascii_uppercase]
vowels=['A','E','I','O','U']
consonant=[x for x in alphabets if x not in vowels]
def swapping_encrypt(string):
    r=""
    for i in string.upper():
        if i==" ":
            r+=" "
        elif i=="\n":
            r+="\n"
        elif i in vowels:
            r+=vowels[::-1][vowels.index(i)]
        else:
            r+=consonant[::-1][consonant.index(i)]
    return r

if __name__=="__main__":
    pass