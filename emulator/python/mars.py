#!/usr/bin/env python3

# Sample MARS # based loosly on subset of MARS Spec draft 1.3
# It does not support:
#   TSRs
#   CapabilityGet
# It does support SequenceEvent() which was dropped from the spec.

# Demo must include desired HW layer and this MARS.
# Author: Tom Brostrom, CPVI

from threading import Lock, current_thread
from enum import Enum

class PT(Enum): # TODO: incomplete
    PCRS = 1
    MAX_DIGEST = 2
    KEY_SIGN = 3
    KEY_SKDF = 4
    KEY_AKDF = 5
    ALG_HASH = 6
    ALG_SIGN = 7

# convert int i to big endian array of n bytes
def int2bebar(i, n):
    return bytes([i>>(j<<3) & 0xff for j in reversed(range(n))])

class MARS_RoT:

    def __init__(self, hw, secret, bsize, debug=False):
        self.debug = debug
        if debug: print('Provisioning of new MARS device')
        assert len(secret) == hw.len_skey
        assert bsize > 0 and bsize <= 32
        self.hw = hw                    # hardware, i.e. Crypt methods
        self.CryptXkdf = hw.CryptAkdf if hw.CryptAkdf else hw.CryptSkdf
        self.PS = secret                # Primary Seed
        self.bsize = bsize              # PCR bank size
        self.hobj = None
        self.seqpcr = None
        self.lock = Lock()
        self.thread = None

        self.PCR = [bytes(self.hw.len_digest) for _ in range(self.bsize)]
        # init TSR
        self.failure = False
        self.Lock()
        self.hw.CryptSelfTest(True)
        self.CryptDpInit()
        self.Unlock()
        

    # MANAGEMENT API

    # determine if locked by the caller
    def locked(self):
        return self.lock.locked() and self.thread == current_thread()

    def SelfTest(self, fullTest):
        assert self.locked()
        if not failure:
            failure = not self.hw.CryptSelfTest(fullTest)
        return not failure

    def Lock(self):
        assert not self.locked()
        self.lock.acquire()
        assert not self.thread
        self.thread = current_thread()

    def Unlock(self):
        assert self.locked()
        self.hobj = None
        # other cleanup?
        self.thread = None
        self.lock.release()

    # TODO: incomplete
    def CapabilityGet(self, pt):
        if pt == PT.PCRS:
            return self.bsize
        # if pt == PT.

    # SUPPORT FUNCTIONS

    def dump(self):
        assert self.locked()
        print('--------------------------')
        print('MARS PRIVATE CONFIGURATION')
        print('     PS:', self.PS.hex())
        print('     DP:', self.DP.hex())
        for i in range(self.bsize):
            print(' PCR[' + str(i) + ']: ' + self.PCR[i].hex())
        print('--------------------------')

    def CryptDpInit(self):
        self.DP = self.hw.CryptSkdf(self.PS, b'D', b'dbg' if self.debug else b'prd')

    def CryptSnapshot(self, regsel, ctx):
        assert (regsel >> self.bsize) == 0   # no stray bits!
        # TODO: Dynamic PCRs, if any, are written at this point
        h = self.hw.hashmod.new()
        h.update(int2bebar(regsel, 4))
        for i in range(self.bsize):
            if (1<<i) & regsel:
                h.update(self.PCR[i])
        h.update(ctx)
        return h.digest()

    # SEQUENCED PRIMITIVES

    def SequenceHash(self):
        assert self.locked()
        assert not self.hobj
        self.hobj = self.hw.hashmod.new()

    # SequenceEvent support was dropped from the spec since this was
    # seen as a simple convenience function, and not a primitive.
    def SequenceEvent(self, ipcr):
        assert ipcr >= 0 and ipcr < self.bsize
        assert self.locked()
        assert self.seqpcr is None
        self.seqpcr = ipcr
        self.SequenceHash()

    def SequenceUpdate(self, data):
        assert self.locked()
        assert self.hobj
        self.hobj.update(data)

    def SequenceComplete(self):
        assert self.locked()
        assert self.hobj
        dig = self.hobj.digest()
        self.hobj = None
        if self.seqpcr is not None:
            self.PcrExtend(self.seqpcr, dig)
            self.seqpcr = None
        return dig

    # INTEGRITY COLLECTION

    def PcrExtend(self, i, dig):
        assert self.locked()
        assert i >= 0 and i < self.bsize
        self.PCR[i] = self.hw.CryptHash(self.PCR[i] + dig)

    def RegRead(self, i):
        assert self.locked()
        assert i >= 0 and i < self.bsize
        return self.PCR[i]

    # KEY MANAGEMENT

    def Derive(self, regsel, ctx):
        assert self.locked()
        snapshot = self.CryptSnapshot( regsel, ctx )
        return self.hw.CryptSkdf(self.DP, b'X', snapshot)

    def DpDerive(self, regsel, ctx):
        assert self.locked()
        if ctx == None:
            self.CryptDpInit()
            # self.DP = self.hw.CryptSkdf(self.PS, b'D', b'')
        else:
            snapshot = self.CryptSnapshot( regsel, ctx )
            self.DP = self.hw.CryptSkdf(self.DP, b'D', snapshot)

    def PublicRead(self, restricted, ctx):
        assert self.locked()
        assert self.hw.CryptAkdf
        label = b'R' if restricted else b'U' # b'S' ??
        key = self.hw.CryptAkdf(self.DP, label, ctx)
        return key.public_key()

    # ATTESTATION

    def Quote(self, regsel, nonce, ctx):
        assert self.locked()
        snapshot = self.CryptSnapshot( regsel, nonce )
        AK = self.CryptXkdf(self.DP, b'R', ctx)
        if (self.hw.CryptAkdf):
            print('AK =', AK.public_key().export_key(format='PEM'))
            #print('AKpub', pem)
        else:
            print('AK =', AK.hex())
        return self.hw.CryptSign(AK, snapshot)

    def Sign(self, ctx, dig):
        assert self.locked()
        assert ctx # must not be Null
        key = self.CryptXkdf(self.DP, b'U', ctx)   # b'S' ??
        return self.hw.CryptSign(key, dig)

    # need to combine iskey and restricted into single parameter ??
    def SignatureVerify(self, restricted, ctx, dig, sig):
        assert self.locked()
        label = b'R' if restricted else b'U' # b'S' ??
        key = self.CryptXkdf(self.DP, label, ctx)
        return self.hw.CryptVerify(key, dig, sig)

if __name__ == '__main__':

    from os import urandom
    from sys import argv
    if len(argv) != 2:
        print('Usage:', argv[0], '<hardware module>')
        exit()
    from importlib import import_module
    hw = import_module('hw_' + argv[1])

    if (hw.len_skey == 16):
        secret = b'A 16-byte secret'
    else:
        secret = b'Here are thirty two secret bytes'

    mars = MARS_RoT(hw, secret, 4, True)

    dig = hw.CryptHash(b'this is a test')
    print('dig =', dig.hex())
    mars.Lock()
    mars.SequenceHash()
    mars.SequenceUpdate(b'this is ')
    mars.SequenceUpdate(b'a test')
    dig = mars.SequenceComplete()
    mars.Unlock()
    print('dig =', dig.hex())

    mars.Lock()
    mars.PcrExtend(0, dig)
    dig = mars.RegRead(0)
    print('PCR 0 ', dig.hex())

    mars.SequenceEvent(1)
    mars.SequenceUpdate(b'this is a ')
    mars.SequenceUpdate(b'test')
    mars.SequenceComplete()
    assert dig == mars.RegRead(1)

    cdi = mars.Derive(1, b'CompoundDeviceID')
    mars.Unlock()
    print('CDI', cdi.hex())

    # nonce = urandom(16)
    nonce = b'Q' * mars.hw.len_digest

    mars.Lock()
    sig = mars.Quote(1<<0, nonce, b'')
    mars.Unlock()
    print('SIG ', sig.hex())

    mars.Lock()
    mars.dump()
    mars.DpDerive(0, b'XYZZY')
    mars.dump()
    sig = mars.Quote(1<<0, nonce, b'')
    print('SIG ', sig.hex())

    # dig = mars.CryptSnapshot(1<<0, nonce)
    dig = hw.CryptHash(b'\x00\x00\x00\x01' + mars.RegRead(0) + nonce)
    print('dig ', dig.hex())
    print('Verified? ', 'Success' if mars.SignatureVerify(True, b'', dig, sig) else 'FAIL')

    cdi = mars.Derive(1, b'CompoundDeviceID')
    print('CDI2', cdi.hex())
    mars.DpDerive(0, None)
    cdi = mars.Derive(1, b'CompoundDeviceID')
    print('CDI1', cdi.hex())

    # IDevID tests
    print('IDevID signature test')
    dig = hw.CryptHash(b'Initial Device Identity')
    sig = mars.Sign(b'IDevID', dig)
    print('Verified? ', 'Success' if mars.SignatureVerify(False, b'IDevID', dig, sig) else 'FAIL')

    if hw.CryptAkdf:
        pub = mars.PublicRead(True, b'')
        pem = pub.export_key(format='PEM')
        print('AKpub', pem)
        # pub = mars.PublicRead(True, b'ak2')
        # pub = mars.PublicRead(False, b'IDevID')
    mars.Unlock()
