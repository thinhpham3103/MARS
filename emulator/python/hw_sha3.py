#!/usr/bin/env python3

# Sample Crypt primitives based on SHA3-256
# Requires pycryptodome 3.14.0
# Tom Brostrom, CPVI

from Crypto.Hash import SHA3_256
from Crypto.Hash import KMAC256
hashmod = SHA3_256

len_digest = hashmod.digest_size
len_sign = 32
len_skey = 32
alg_hash = 0x27  # TPM_ALG_SHA3_256

def SelfTest():
    dig = hashmod.new(b'PYTHON').digest()
    exp = bytes.fromhex('6f5cb49ed7bccd9ce5b135dc8fa89523503216d0e3082307c80e4cd54c0e52d0')
    return dig == exp

def CryptHash(data):
    return hashmod.new(data).digest()

# from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-draft.pdf
def CryptSkdf(K, label, context):
    return KMAC256.new(key=K, data=context, mac_len=32, custom=label).digest()

CryptAkdf = None

def CryptSign(K, h):
    return KMAC256.new(key=K, data=h.digest(), mac_len=32, custom=b'').digest()

def CryptVerify(K, msg, sig):
    return sig == KMAC256.new(key=K, data=msg, mac_len=32, custom=b'').digest()


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


# Demonstrate use of KMAC256
# Test vector is Sample #4 from
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf

    K = b'@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'
    X = b'\x00\x01\x02\x03' # X = bytes.fromhex('00010203')
    S = b'My Tagged Application'
    res = KMAC256.new(key=K, data=X, mac_len=64, custom=S).digest()
    print('Result =', res.hex())
    exp = bytes.fromhex('20 C5 70 C3 13 46 F7 03 C9 AC 36 C6 1C 03 CB 64 C3 97 0D 0C FC 78 7E 9B 79 59 9D 27 3A 68 D2 F7 F6 9D 4C C3 DE 9D 10 4A 35 16 89 F2 7C F6 F5 95 1F 01 03 F3 3F 4F 24 87 10 24 D9 C2 77 73 A8 DD')
    print(res == exp)

