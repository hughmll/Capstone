from Crypto.Cipher import AES
from PBKDF import *

#encrypted_data=[]
user_input = b'atlanticwax99'

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
        encrypted_file.write(nonce) #writes 16 byte nonce to file first
        encrypted_file.write(tag) #followed by 16 byte tag
        encrypted_file.write(cipher_text) #followed by the ciphertext

encryption(user_input)

def decryption(user_input):
    password = user_input
    key = key_derivation(password)
    with open("Encrypted_conf_file.txt",  "rb") as encrypted_data:
        nonce = encrypted_data.read(16) #reads first 16 bytes of encrypted file to grab nonce value for passing to key object generator
    with open("Encrypted_conf_file.txt", "rb") as encrypted_data:
        encrypted_data.seek(16) #opens file again and moves  to 16 byte offset from beginning of file
        tag = encrypted_data.read(16) #reads only 16 bytes after 16 byte offset to get MAC tag for verification
    with open("Encrypted_conf_file.txt", "rb") as encrypted_data:
        encrypted_data.seek(32) #moves to 32 byte offset from beginning of file (to skip nonce and tag)
        cipher_text2 = encrypted_data.read() # reads rest of file after offset to get ciphertext only
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    deciphered_text = cipher.decrypt_and_verify(cipher_text2, tag)
    print(deciphered_text.decode())

decryption(user_input)