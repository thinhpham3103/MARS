#!/usr/bin/env python3
# Implements KMAC256 from NIST SP800-185
# requires pycryptodome 3.11.0
# Author: Tom Brostrom

import cSHAKE256 as myc

def KMAC256(K, X, L, S):
    """• K is a key bytearray
    • X is the main input bytearray
    • L is an integer representing the requested output length in bits
    • S is an optional customization bytearray
    """
    newX = myc._bytepad( myc._encode_str(K), 136) + X + myc._right_encode(L)
    c = myc.new(data=newX, custom=S, N=b'KMAC')
    return c.read(L//8)

# Demonstrate use of KMAC256
# Test vector is Sample #4 from
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf

if __name__ == '__main__':

    K = b'@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'
    X = b'\x00\x01\x02\x03' # X = bytes.fromhex('00010203')
    S = b'My Tagged Application'
    res = KMAC256(K, X, 512, S)
    print('Result =', res.hex())
    exp = bytes.fromhex('20 C5 70 C3 13 46 F7 03 C9 AC 36 C6 1C 03 CB 64 C3 97 0D 0C FC 78 7E 9B 79 59 9D 27 3A 68 D2 F7 F6 9D 4C C3 DE 9D 10 4A 35 16 89 F2 7C F6 F5 95 1F 01 03 F3 3F 4F 24 87 10 24 D9 C2 77 73 A8 DD')
    print(res == exp)
