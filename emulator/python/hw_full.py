#!/usr/bin/env python3

# Sample Crypt primitives based on SHA256 and ECC/DSS for MARS
# based loosly on subset of MARS Spec draft 0.31
# Requires pycryptodome
# Tom Brostrom, CPVI

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import random

hashalg = 0xB  # TPM_ALG_SHA256
drbg_init = random.seed

def drbg(n):
    i = random.getrandbits(8*n)
    # convert int i to little endian array of n bytes
    b = bytes([i>>(j<<3) & 0xff for j in range(n)])
    # print(n, b.hex())
    return b

def SelfTest():
    return True # TODO: write some real tests

hashmod = SHA256
# CryptHasher must support .digest_size, .update(), .digest()

def CryptHash(data):
    return hashmod.new(data).digest()

def CryptSkdf(key, x, y):
    drbg_init(key + x + y)
    return drbg(len(key))

def CryptAkdf(key, x, y):
    print('Akdf key', key.hex(), 'x', x.hex(), 'y', y.hex())
    drbg_init(key + x + y)
    new = ECC.generate(curve='P-256', randfunc=drbg)
    print('Akdf:', hex(new.d)[2:])
    return new

def CryptSign(key, msg):
    # signer = DSS.new(key, 'fips-186-3')
    signer = DSS.new(key, 'deterministic-rfc6979')
    return signer.sign(msg)
    # return DSS.new(key, 'fips-186-3').sign(msg)

class Hasher_dummy:  # to make DSS Verify happy
    def __init__(self, data=b''): 
        self.dig = data
    def digest(self):
        return self.dig

def CryptVerify(pub, dig, sig):
    # verify = DSS.new(pub, 'fips-186-3').verify
    verify = DSS.new(pub, 'deterministic-rfc6979').verify
    rc = True
    try:
        verify(Hasher_dummy(dig), sig)
    except ValueError:
        rc = False
    # print('Good' if rc else 'bad')
    return rc


if __name__ == '__main__':
    from os import urandom

    secret = bytes.fromhex('101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f')

    dig = CryptHash(b'this is a test')
    print('dig =', dig.hex())
    h = hashmod.new()
    h.update(b'this is ')
    h.update(b'a test')
    dig = h.digest()
    print('dig =', dig.hex())

    prv = CryptAkdf(secret, b'R', b'')
    pub = prv.public_key()

    sig = CryptSign(prv, h)
    print('sig =', sig.hex())

    CryptVerify(pub, dig, sig)
