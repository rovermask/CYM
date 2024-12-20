def caesar_cipher(plain_text,key):
    cipher_text=""
    for i in plain_text:
        if(i.isupper()):
            cipher_text+=chr(((ord(i)+key)-65)%26 + 65)
        else:
            cipher_text+=chr(((ord(i)+key)-97)%26 + 97)
    return cipher_text

if __name__=="__main__":
    print(caesar_cipher("Vibhum",5))
    pass