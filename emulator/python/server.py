#!/usr/bin/env python3

# MARS Service Provider (or Relying Party or Verifier) demonstration 
# T. Brostrom, Cyber Pack Ventures, Inc.

# receive connection from client
# challenge client with nonce
# evaluate reply

import os
import subprocess
import time
import socket
import cbor2 as cbor
from mars_util import Snapshot

from importlib import import_module
global hw
hw = None
# hwtable = {mod:import_module('hw_' + mod) for mod in ['she', 'ascon', 'full', 'sha3' ] }
hwtable = {}
for mod in ( 'she', 'ascon', 'full', 'sha2', 'sha3' ):
    hwtable[mod] = import_module('hw_' + mod)



#########################################################
# ENDORSER CODE:
# format is { mid:AK, ... }
dev_db = { 
           bytes.fromhex('b4b28f261159ad999f946ffa29026ead') : # SHE
           bytes.fromhex('5c7f0e9a8b6a6c24f083f65f9e5e2902'),
           bytes.fromhex('7847c4bfdc78e1fa91a1b819b4a75ed8') : # ASCON
           bytes.fromhex('12eea89fb0a5415da2c3b121be47f7d7'),
           bytes.fromhex('0f2a4cbe528c3af705b99aacd89ac9d4da660e960d2f89215be7f9ae1c86f824') : # SHA256
           bytes.fromhex('563c94e783a2d43e2248a874595ece012a560b073a9fccf68b32e0e2d9195c47'),
           bytes.fromhex('bb7a6229485f9b43a4ac58ca64bc3ea7fc8d2d7f8f7e7ab5cb544959132bb69b') : # SHA3_256
           bytes.fromhex('0f2574379d2f5546af006496362a040355cd1f09bb37b5e8e0ade40b7623d680'),
         }

# Check if digest is properly signed by mid's shared AK
def endorse(url, mid, dig, sig):
    print('  ENDORSER', url)
    print('  Query for device', mid.hex())
    try:
        AK = dev_db[mid]
    except:
        print('Unknown device', mid.hex())
        return None
    print('  Found AK', AK.hex())
    print('  Signature check:')
    print('     reported:', sig.hex())
    rc = hw.CryptVerify(AK, dig, sig)
    print('   ', 'Pass' if rc else 'FAIL')
    return rc

# Verify CEL, Canonical Event Log
# CELR format:  (recnum, index, digest_list, content)
def cel_verify(cel, pcrs):
    print('VERIFYING CEL')
    for recnum,index,diglist,content in cel:
        pcr_e = bytes(hw.hashmod.digest_size)
        print('Processing CEL Record', recnum, ', PCR', index)
        for hashalg,dig in diglist:
            assert hashalg == hw.hashalg
            print('   ', dig.hex())
            # Extend PCR_Expected
            pcr_e = hw.CryptHash(pcr_e + dig)
        print('  expected:', pcr_e.hex())
        if pcr_e != pcrs[index]:
            print('  reported:', pcrs[index].hex())
            return False
    return True

#########################################################
# RELYING PARTY CODE:

trusted_e = [ 'https://ez_iot.com/endorse' ]

# Check that the endorser URL is trusted
def chk_e(url):
    return url in trusted_e

def reply(msg):
    print(str(msg)[2:-1])
    s.sendto(msg, client)

print('RELYING PARTY')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# host = socket.gethostname()
s.bind(('', 21345))

while True:
    # get request from client attester
    blob, client = s.recvfrom(1024)
    mid, bsize = cbor.loads(blob)
    print(' Client:', client)
    print('MARS Id:', mid.hex())
    print('  bsize:', bsize)

    # send challenge to attester
    nonce = os.urandom(16)
    pcrsel = (1<<bsize) - 1 # ask for all PCRs
    print('Sending nonce', nonce.hex(), ' pcrsel', hex(pcrsel))
    s.sendto(cbor.dumps((nonce, pcrsel)), client)

    # receive evidence, aka attestation blob
    blob, client = s.recvfrom(2048)  # should specify client in param

    # Convert attestation blob from CBOR to Python representation
    try:
        att = cbor.loads(blob)
    except Exception:
        reply(b'bad blob received')
        continue

    mod   = att['HW']
    print('   hw:', mod)
    hw = hwtable[mod]
    mid   = att['MID']
    url   = att['Endorser']
    sig_r = att['Signature']
    pcrs  = att['PCRs']
    cel   = att['CEL']
    crt   = att['AkCrt'] if hw.CryptAkdf else None

    print('nonce:', nonce.hex())
    print('  sig:', sig_r.hex())

    # reconstruct snapshot
    dig = Snapshot(hw, bsize, pcrsel, pcrs, nonce).digest()

    # verify the endorser and signature of the snapshot
    if crt:
        print('Asymmetric')
        # Check endorsement of AK
        # Verify that the provided AK-Cert is acceptable
        p = subprocess.run(['openssl', 'verify', '-verbose', '-CAfile', 'keys/ez.crt' ], input=crt)
        if p.returncode:
           reply(b'Invalid AK Certificate')
           continue
        print('AK Cert is good')

        # Verify the signature
        akpub = hw.ECC.import_key(crt)
        r = hw.CryptVerify(akpub, dig, sig_r)
    else:
        print('Symmetric')
        # Check if endorser is trusted
        if not chk_e(url):
            reply(b'Unknown endorser: ' + url )
            continue
        print('Trusted endorser', url)
        # Verify the signature
        r = endorse(url, mid, dig, sig_r)
    if not r:
        reply(b'Invalid signature.')
        continue
    print('Signature is valid. PCR(s) are accurate.')

    # Verify CEL matches signed PCRs
    if not cel_verify(cel, pcrs):
        reply(b'PCR mismatch. CEL is invalid.')
        continue
    print('CEL is accurate.')

    # Could assess PCR and/or CEL digests here

    from datetime import date
    msg = 'Access granted. Date is ' + date.today().strftime('%B %d, %Y.')
    reply(bytes(msg, encoding='UTF-8'))
    # reply(cbor.dumps(msg))
