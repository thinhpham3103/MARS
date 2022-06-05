#!/usr/bin/env python3

# Sample Crypt primitives based on AES hash, CMAC and KDF for MARS
# Implements algorithms specified in AUTOSAR Secure Hardware Extensions (SHE)
# Author: Tom Brostrom, CPVI

# AES implementation from:
# https://github.com/ricmoo/pyaes/blob/master/pyaes/aes.py
import aes
import aes_mphash as hashmod

len_digest = hashmod.digest_size
len_sign = 16
len_skey = 16
alg_hash = 0x81  # TPM_ALG_? AES_MP

# convert int i to big endian array of n bytes
def int2bebar(i, n):
    return bytes([i>>(j<<3) & 0xff for j in reversed(range(n))])

# SHE only supports ECB (default) and CBC modes
# See tests below for examples
cipher_ecb = aes.AESModeOfOperationECB # (key).encrypt(data)
cipher_cbc = aes.AESModeOfOperationCBC # (key, iv).encrypt(data)

# Left shift bytearray by 1 bit. Return MSB.
def ls1(a):
    C = 0
    for i in reversed(range(len(a))):
        b = (a[i] << 1) | C
        a[i] = b & 0xff 
        C = b >> 8
    return C

# XOR Byte Arrays # compute x = x ^ y
def xba(x, y):
    assert len(x) == len(y)
    for i in range(len(x)):
        x[i] ^= y[i]

# Simplified CMAC algorithm for a single block.
def cmac1(K, blk):
    assert len(blk) == 16
    E = cipher_ecb(K).encrypt
    mtk = bytearray(E(bytes(16)))       # create the Tweak sub-key k0
    if ls1(mtk): mtk[15] ^= 0x87        # turn k0 into k1
    xba(mtk, blk)                       # create Mn' from k1 ^ blk
    return E(bytes(mtk))                # then encrypt Mn'

# Full CMAC algorithm.
# Verify with: https://artjomb.github.io/cryptojs-extension/
def cmac(K, msg):
    # print('key =', K.hex())
    E = cipher_ecb(K).encrypt
    mtk = bytearray(E(bytes(16)))       # create the Tweak sub-key k0
    if ls1(mtk): mtk[15] ^= 0x87        # turn k0 into k1

    f = len(msg) >> 4   # full blocks in msg
    r = len(msg) & 0xf  # remainder bytes in last block of msg
    # print('msg =', msg.hex(), " f =", f, ' r =', r)
    if r or not f:                      # partial block, or empty msg
        if ls1(mtk): mtk[15] ^= 0x87    # turn k1 into k2
        last = msg[-r:] + b'\x80' + bytes(15-r)
    else:
        f -= 1
        last = msg[-16:]

    # XOR the tweak sub-key (k1 or k2 in mtk) with last block
    xba(mtk, last)                      # Create Mn': mtk ^= last

    # process all but the last block
    V = bytearray(16)
    for i in range(f):
        xba(V, msg[i<<4:(i+1)<<4])      # V ^= Mi
        V = bytearray(E(bytes(V)))      # V = E(V)

    # process the last tweaked block Mn' in mtk
    xba(V, mtk)                         # V ^= Mn'
    V = E(bytes(V))                     # V = E(V)
    return V

def CryptHash(msg):
    return hashmod.new(msg).digest()

CryptSign = cmac1

def CryptVerify(key, dig, sig):
    return sig == CryptSign(key, dig)

# Key Derivation Function
def shekdf(K, C):
    return CryptHash(K + b'\x01\x01' + C + b'\x00')

def CryptSkdf(key, x, y):
    return shekdf(key, x + y)

CryptAkdf = None

def CryptSelfTest(fullTest):
    return True # TODO: write some real tests

if __name__ == "__main__":

    # ECB TESTS
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    c = cipher_ecb(key)
    pt  = bytes.fromhex('00112233445566778899aabbccddeeff')
    exp = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    out = c.encrypt(pt)
    print('ECB1 TEST:', 'pass' if out == exp else 'FAIL')
    out = c.decrypt(out)
    print('ECB2 TEST:', 'pass' if out == pt else 'FAIL')

    # CBC TESTS

    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    e = cipher_cbc(key, iv).encrypt

    pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    exp = bytes.fromhex('7649abac8119b246cee98e9b12e9197d')
    out = e(pt)
    print('CBC1 TEST:', 'pass' if out == exp else 'FAIL')

    pt  = bytes.fromhex('ae2d8a571e03ac9c9eb76fac45af8e51')
    exp = bytes.fromhex('5086cb9b507219ee95db113a917678b2')
    out = e(pt)
    print('CBC2 TEST:', 'pass' if out == exp else 'FAIL')
    
    # HASH TESTS

    msg = bytes.fromhex(
        '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51')
    exp = bytes.fromhex('c7277a0dc1fb853b5f4d9cbd26be40c6')
    out = CryptHash(msg)
    print('HASH TEST:', 'pass' if out == exp else 'FAIL')

    hobj = hashmod.new()
    hobj.update(msg[0:4])
    hobj.update(msg[4:21])
    hobj.update(msg[21:32])
    out = hobj.digest()
    print('SEQ TEST:', 'pass' if out == exp else 'FAIL')

    # CMAC TESTS

    K   = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    msg = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    exp = bytes.fromhex('070a16b46b4d4144f79bdd9dd04a287c')
    out = cmac(K, msg)
    print('CMAC TEST:', 'pass' if out == exp else 'FAIL')
 
    out = cmac1(K, msg)
    print('CMAC1 TEST:', 'pass' if out == exp else 'FAIL')

    # SIGN TESTS
    h = hashmod.new()
    h.update(b'check 1 2 3')
    sig = CryptSign(K, h.digest())

    h = hashmod.new()
    h.update(b'check 1 2 3')
    print('SIGN TEST:', 'pass' if CryptVerify(K, h.digest(), sig) else 'FAIL')

    # KDF TEST

    K   = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    exp = bytes.fromhex('118a46447a770d87828a69c222e2d17e')
    out = CryptSkdf(K, b'SHE', b'')
    print('KDF TEST:', 'pass' if out == exp else 'FAIL')
