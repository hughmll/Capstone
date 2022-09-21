from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA3_512
import timeit


def key_derivation(user_input):
    #password = b'purplemonkeydishwasher'
    password = user_input
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





