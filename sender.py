import hashlib
import hmac
import rsa
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad

# generating RSA public and private keys
sender_public_key, sender_private_key = rsa.newkeys(1024)
receiver_public_key, receiver_private_key = rsa.newkeys(1024)

with open("sender_public.pem", "wb") as f:
    f.write(sender_public_key.save_pkcs1("PEM"))

with open("sender_private.pem", "wb") as f:
    f.write(sender_private_key.save_pkcs1("PEM"))

with open("receiver_public.pem", "wb") as f:
    f.write(receiver_public_key.save_pkcs1("PEM"))

with open("receiver_private.pem", "wb") as f:
    f.write(receiver_private_key.save_pkcs1("PEM"))

#loading the RSA sender private and receivers public key
with open("receiver_public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("sender_private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

#generating salt:
#simple_key = get_random_bytes(32)
#print(simple_key)

salt = '\x855\x9d\x13\x11\xce\x84\x98\x11\x86\xbc\x00\x9e\x8c\xfc\xe0\xa9\xecB<\xf9jOL\xfc\x87\x8e0\xe3\xcc&\x9f'
password = "encryption"

AES_key = PBKDF2(password, salt, dkLen=32)
print("AES key:")
print(AES_key)

# getting message to send from text file:
with open("message.txt", "rb") as f:
    message = f.read()

print("message:")
print(message)

# encrypting message using AES key
cipher = AES.new(AES_key, AES.MODE_CBC)
encrypted_message = cipher.encrypt(pad(message, AES.block_size))

# encrypting AES key with receiver's RSA public key
encrypted_AES_key = rsa.encrypt(AES_key, public_key)

#generate hmac
def gen_hmac(key, message):
    key = bytes(key, 'utf-8')
    h = hmac.new(key, message, hashlib.sha256)
    return h.digest()

shared_key = "secret_key"
hmac_tag = gen_hmac(shared_key, encrypted_message + encrypted_AES_key)


#send encrypted message, encrypted AES key, hmac_tag to file
with open("Transmitted_Data.txt", "wb") as f:
    f.write(encrypted_AES_key)
    f.write(hmac_tag)
    f.write(encrypted_message)



