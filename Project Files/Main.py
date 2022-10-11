from PBKDF import *
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA3_512
from Crypto.Cipher import AES
import time
from gtts import gTTS
import os
import playsound
from colorama import Fore, Back, Style

var_dict = {}
os.system('color f0')

def speak(speech):
    tts = gTTS(text=speech, lang='en', tld='com.au')

    filename = "voice.mp3"
    tts.save(filename)
    playsound.playsound(filename)
    os.remove(filename)

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
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) # new key object instantiated for decryption
    deciphered_text = cipher.decrypt_and_verify(cipher_text2, tag) #ciphertext decrypted and tag verified
    print(deciphered_text.decode())

with open("test_conf_file.txt", "rb") as bytes_text:
    data = bytes_text.read()

def file_parser(x):
    data = x.decode().split("\n")
    for item in data:
        if "[Interface]" in item:
            item.replace("[Interface]", "")
        elif "\r" in item:
            item = item.replace("\r", "")
            key = item.split(" = ")[0]
            value = item.split(" = ")[1]
            var_dict[key] = value
        else:
            key = item.split(" = ")[0]
            value = item.split(" = ")[1]
            var_dict[key] = value

print("""
 ######  ########  ######  ##     ## ########  ######## 
##    ## ##       ##    ## ##     ## ##     ## ##       
##       ##       ##       ##     ## ##     ## ##       
 ######  ######   ##       ##     ## ########  ######   
      ## ##       ##       ##     ## ##   ##   ##       
##    ## ##       ##    ## ##     ## ##    ##  ##       
 ######  ########  ######   #######  ##     ## ########
 
######## #### ##       ######## 
##        ##  ##       ##       
##        ##  ##       ##       
######    ##  ##       ######   
##        ##  ##       ##       
##        ##  ##       ##       
##       #### ######## ######## 

########  ########   #######  ########  #######  ######## ##    ## ########  ######## 
##     ## ##     ## ##     ##    ##    ##     ##    ##     ##  ##  ##     ## ##       
##     ## ##     ## ##     ##    ##    ##     ##    ##      ####   ##     ## ##       
########  ########  ##     ##    ##    ##     ##    ##       ##    ########  ######   
##        ##   ##   ##     ##    ##    ##     ##    ##       ##    ##        ##       
##        ##    ##  ##     ##    ##    ##     ##    ##       ##    ##        ##       
##        ##     ##  #######     ##     #######     ##       ##    ##        ########

""")

print("""Welcome to the secure file prototype: a file encryption and decryption tool. This tool allows you to encrypt
a plaintext file with a password of your choice. The file can then be decrypted by re-entering the password.
The contents of the file before and after decryption will be displayed and read out. Lets get started.\n""")
speak("""Welcome to the prototype file encryption and decryption tool. 
This tool allows you to encrypt a plaintext file with a password of your choice. 
The file can then be decrypted by re-entering the password.
The contents of the file before and after decryption will be displayed and read out. 
Lets get started.""")


print("Please type a password below and press enter to encrypt the test file. You will need this password later to decrypt the file:")
speak("Please type a password below and press enter to encrypt the test file. You will need this password later to decrypt the file")
password = input()
password = password.encode()
if password != "":
    print("\nYou have successfully input a password")
    speak("You have successfully input a password")
else:
    print("No password entered")
    speak("No password entered")
    exit()

#time.sleep(3)

print("\nThe test file will now be encrypted. The encrypted text will be displayed below\n")
speak("The test file will now be encrypted. The encrypted text will be displayed below")
encryption(password)

print("\nPlease enter your password below to decrypt the test file")
speak("Please enter your password below to decrypt the test file")
password = input()
password = password.encode()

print("\nThe test file will now be decrypted. The plaintext will be displayed below\n")
speak("The test file will now be decrypted. The plaintext will be displayed below")
decryption(password)

time.sleep(2)
print("\nThe test file has now been decrypted\n")
speak("The test file has now been decrypted")

file_parser(data)

print(var_dict)
speak(str(var_dict))









