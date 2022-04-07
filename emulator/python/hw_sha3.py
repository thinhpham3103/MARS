#!/usr/bin/env python3

# Sample Crypt primitives based on SHA3-256
# Requires pycryptodome
# Tom Brostrom, CPVI

# requires >= pycryptodome 3.11.0
from Crypto.Hash import SHA3_256
from kmac import KMAC256

hashalg = 0x27  # TPM_ALG_SHA3_256
hashmod = SHA3_256

def SelfTest():
    dig = hashmod.new(b'PYTHON').digest()
    exp = bytes.fromhex('6f5cb49ed7bccd9ce5b135dc8fa89523503216d0e3082307c80e4cd54c0e52d0')
    return dig == exp

def CryptHash(data):
    return hashmod.new(data).digest()

# from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-draft.pdf
def CryptSkdf(K, label, context):
    return KMAC256(K, context, 256, label)

CryptAkdf = None

def CryptSign(key, h):
    return KMAC256(key, h.digest(), 256, b'')

def CryptVerify(key, msg, sig):
    return sig == KMAC256(key, msg, 256, b'')


if __name__ == '__main__':
    print('Selftest', SelfTest())

    secret = bytes.fromhex('101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f')
    print('sec =', secret.hex())

    ak = CryptSkdf(secret, b'R', b'')
    print(' ak =', ak.hex())

    dig = CryptHash(b'this is a test')
    print('dig =', dig.hex())
    h = hashmod.new()
    h.update(b'this is ')
    h.update(b'a test')
    dig = h.digest()
    print('dig =', dig.hex())

    sig = CryptSign(ak, h)
    print('sig =', sig.hex())

    print('sig check', CryptVerify(ak, dig, sig))
