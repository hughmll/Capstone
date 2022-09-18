from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA3_512
from Crypto.Cipher import AES
import timeit


def key_derivation():
    password = b'purplemonkeydishwasher'
    salt = b'A1bV7t6efsp'
    key = PBKDF2(password, salt, dkLen=32, count=50000, hmac_hash_module=SHA3_512)
    return key

#print(key_derivation().hex(sep=' '))
#times=[]

#for i in range(5):
    #start = timeit.default_timer()
    #key_derivation()
    #stop = timeit.default_timer()
    #times.append(stop - start)

#print("Average time taken = " + str(sum(times) / len(times)))

data = "This is plaintext. You can read it"
print(data)


key = key_derivation()
cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
cipher_text, tag = cipher.encrypt_and_digest(data.encode('UTF-8'))

print(cipher_text)

decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
deciphered_text = decipher.decrypt(cipher_text)
print(deciphered_text.decode('UTF-8'))




