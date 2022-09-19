from Crypto.Cipher import AES
from PBKDF import *

encrypted_data=[]

def encryption():
    with open("test_conf_file.txt", "rb") as plaintext_file:
        plaintext_data = plaintext_file.read()
    print(plaintext_data)
    key = key_derivation()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    #print(nonce)
    cipher_text, tag = cipher.encrypt_and_digest(plaintext_data)
    print(cipher_text)
    with open("Encrypted_conf_file.txt", "wb") as encrypted_file:
        encrypted_file.write(nonce)
        encrypted_file.write(cipher_text)
        #encrypted_file.write(cipher_text.hex(sep = ' '))

encryption()

def decryption():
    key = key_derivation()
    with open("Encrypted_conf_file.txt",  "rb") as encrypted_data:
        nonce = encrypted_data.read(16)
        cipher_text2 = encrypted_data.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    deciphered_text = cipher.decrypt(cipher_text2)
    print(deciphered_text)

decryption()