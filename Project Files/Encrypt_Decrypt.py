from Crypto.Cipher import AES
from PBKDF import *

#encrypted_data=[]

def encryption(user_input):
    with open("test_conf_file.txt", "rb") as plaintext_file:
        plaintext_data = plaintext_file.read()
    password = user_input
    key = key_derivation(password)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text, tag = cipher.encrypt_and_digest(plaintext_data)
    print(cipher_text)
    with open("Encrypted_conf_file.txt", "wb") as encrypted_file:
        encrypted_file.write(nonce)
        encrypted_file.write(cipher_text)

#encryption()

def decryption(user_input):
    password = user_input
    key = key_derivation(password)
    with open("Encrypted_conf_file.txt",  "rb") as encrypted_data:
        nonce = encrypted_data.read(16)
        cipher_text2 = encrypted_data.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    deciphered_text = cipher.decrypt(cipher_text2)
    print(deciphered_text.decode())

#decryption()