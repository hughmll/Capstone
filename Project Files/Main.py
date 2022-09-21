from PBKDF import *
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA3_512
from Crypto.Cipher import AES
import time
from gtts import gTTS
import os
import playsound

os.system('color f0')
var_dict = {}

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
        encrypted_file.write(nonce)
        encrypted_file.write(cipher_text)

def decryption(user_input):
    password = user_input
    key = key_derivation(password)
    with open("Encrypted_conf_file.txt",  "rb") as encrypted_data:
        nonce = encrypted_data.read(16)
        cipher_text2 = encrypted_data.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    deciphered_text = cipher.decrypt(cipher_text2)
    print("The deciphered text is: \n ")
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

print("Please enter a password to encrypt the document. You will need this password later to decrypt the document")
speak("Please enter a password to encrypt the document. You will need this password later to decrypt the document")
password = input()
password = password.encode()
if password != "":
    print("You have successfully input a password")
    speak("You have successfully input a password")
else:
    print("No password entered")
    speak("No password entered")

#time.sleep(3)

print("The document will now be encrypted. The ciphertext will be displayed below\n")
speak("The document will now be encrypted. The ciphertext will be displayed below")
encryption(password)

print("\nThe document will now be decrypted. The plaintext will be displayed below\n")
speak("The document will now be decrypted. The plaintext will be displayed below")
decryption(password)

time.sleep(2)
print("\nThe document has now been decrypted\n")
speak("The document has now been decrypted")

file_parser(data)

print(var_dict)
time.sleep(5)









