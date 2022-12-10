from Crypto.Cipher import AES
from PBKDF import *
import sys


#script takes 3 command line  (excluding the script name): input file path, output file path, password for encryption
#For example, to encrypt a configuration file called 'wg.conf', write the encryped output to a file called 'encrypted.txt' with the password 'testpassword
#you would invoke the script as follows: python conf_file_encrypt.py wg.conf encrypted.txt testpassword
#the example above assumes both the script and file to be encrypted are in your current working directory

user_input = sys.argv[3].encode()

def encryption(user_input):
    with open(sys.argv[1], "rb") as plaintext_file:
        plaintext_data = plaintext_file.read()
        print(plaintext_data)
    password = user_input
    key = key_derivation(password)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text, tag = cipher.encrypt_and_digest(plaintext_data)
    #print(cipher_text)
    with open(sys.argv[2], "wb") as encrypted_file:
        encrypted_file.write(nonce) #writes 16 byte nonce to file first
        encrypted_file.write(tag) #followed by 16 byte tag
        encrypted_file.write(cipher_text) #followed by the ciphertext

encryption(user_input)