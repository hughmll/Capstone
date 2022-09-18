from Crypto.Cipher import AES
from PBKDF import *

data = "This is plaintext. You can read it"
print(data)

encrypted_data=[]

def encryption():
    key = key_derivation()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    print(f"nonce = {nonce}")
    cipher_text, tag = cipher.encrypt_and_digest(data.encode('UTF-8'))
    print(cipher_text)
    encrypted_data.append(nonce)
    encrypted_data.append(cipher_text)
    #with open('Encrypted_text_file.txt', 'a') as encrypted_file:
        #encrypted_file.write(nonce.hex(sep = ' '))
        #encrypted_file.write("\n")
        #encrypted_file.write(cipher_text.hex(sep = ' '))


encryption()

def decryption():
    key = key_derivation()
    cipher = AES.new(key, AES.MODE_EAX, nonce=encrypted_data[0])
    deciphered_text = cipher.decrypt(encrypted_data[1])
    print(deciphered_text.decode('UTF-8'))

decryption()