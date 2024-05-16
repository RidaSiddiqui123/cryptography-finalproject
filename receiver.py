import hashlib
import hmac

import rsa
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

shared_key = "secret_key"

#loading the RSA sender private and receivers public key
#with open("receiver_public.pem", "rb") as f:
 #   public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("receiver_private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

#getting the data from file
with open("Transmitted_Data.txt", "rb") as f:
    encrypted_AES_key = f.read(128)
    hmac_tag = f.read(32)
    encrypted_message = f.read()


#verifying the hmac:
def verify_hmac(key, message, hmac_tag):
    key = bytes(key, 'utf-8')
    h = hmac.new(key, message, hashlib.sha256)
    if h.digest() == hmac_tag:
        print("Verified")
        return True
    else:
        print("Not Verified")
        return False

verify_hmac(shared_key, encrypted_message + encrypted_AES_key, hmac_tag)


#decrypting AES key with receivers RSA private key
AES_key = rsa.decrypt(encrypted_AES_key, private_key)
print("AES Key:")
print(AES_key)

#decrypting message using AES key
cipher = AES.new(AES_key, AES.MODE_CBC)
message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
print("message:")
print(message)




