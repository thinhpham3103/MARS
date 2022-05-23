#!/usr/bin/env python3

"""
Sample Crypt primitives based on Ascon for MARS
T. Brostrom
"""

from ascon import ascon_hash, ascon_encrypt, ascon_decrypt
CryptHash = ascon_hash

len_digest = 32
len_sign = 16
len_skey = 16
alg_hash = 0x80  # TPM_ALG_? ASCON_HASH

def CryptSelfTest(fullTest):
    return True # TODO: write some real tests

# Simple hasher if update is not natively supported
class hash:
    digest_size = len(CryptHash(b''))
    def __init__(self, msg=b''):
        # self.digest_size = CryptHasher.digest_size
        self.partial = msg

    def update(self, msg):
        self.partial += msg

    def digest(self):
        return CryptHash(self.partial)

class hashmod:
    digest_size = hash().digest_size
    def new(data=b''):
        return hash(data)

def CryptSkdf(k, label, context):
    label += bytes(16-len(label))
    return ascon_encrypt(k, label, context, b'')

CryptAkdf = None

def CryptSign(key, dig):
    # ascon_encrypt(key, nonce, associateddata, plaintext)
    label = b'Z'
    label += bytes(16-len(label))
    print("SIGN: key", key.hex())
    print("SIGN: nnc", label.hex())
    print("SIGN:  ad", dig.hex())
    sig = ascon_encrypt(key, label, dig, b'')
    print("SIGN: sig", sig.hex())
    return sig

def CryptVerify(key, dig, sig):
    # ascon_decrypt(key, nonce, associateddata, ciphertext)
    label = b'Z'
    label += bytes(16-len(label))
    return ascon_decrypt(key, label, dig, sig) != None

