#include <string.h> // for memset()
#include <stdio.h>
#include "mars.h"

static void hexout(const char *msg, const void *buf, uint16_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}

static bool lock = false;

MARS_RC MARS_Lock()
{
    if (lock)
        return MARS_RC_LOCK;
    lock = true;
    return MARS_RC_SUCCESS;
}

MARS_RC MARS_Unlock()
{
    if (!lock)
        return MARS_RC_LOCK;
    lock = false;
    return MARS_RC_SUCCESS;
}

#define CHECKRC if (rc) { printf("rc=%d, line=%d\n", rc, __LINE__); exit(rc); }

main(int argc, char **argv)
{
MARS_RC rc;
bool flag = 0;
size_t outlen;
uint16_t diglen, siglen, keylen, halg;

    MARS_Lock();

    printf("SelfTest = %d\n", MARS_SelfTest(true));

    rc = MARS_CapabilityGet(MARS_PT_LEN_DIGEST, &diglen, sizeof(diglen));
    if (rc) {
        printf("usage: LD_PRELOAD=<mars.so> %s\n", argv[0]);
        exit(1);
    }
    MARS_CapabilityGet(MARS_PT_LEN_SIGN, &siglen, sizeof(siglen));
    MARS_CapabilityGet(MARS_PT_LEN_KSYM, &keylen, sizeof(keylen));
    MARS_CapabilityGet(MARS_PT_ALG_HASH, &halg, sizeof(halg));

    printf("Hash alg = 0x%x\n", halg);

uint8_t dig[diglen];
uint8_t sig[siglen];
uint8_t id[keylen];
uint8_t nonce[diglen];

    char msg1[] = "this is a test";
    rc = MARS_SequenceHash();
    CHECKRC
    outlen = 0;
    rc = MARS_SequenceUpdate(msg1, sizeof(msg1)-1, 0, &outlen);
    CHECKRC
    outlen = sizeof(dig);
    rc = MARS_SequenceComplete(dig, &outlen);
    CHECKRC

    hexout("dig", dig, outlen);

    rc = MARS_PcrExtend(0, dig);
    CHECKRC
    rc = MARS_RegRead(0, dig);
    CHECKRC
    hexout("PCR0", dig, sizeof(dig));

    rc = MARS_Derive(1, "CompoundDeviceID", 16, id);
    CHECKRC
    hexout("CDI", id, sizeof(id));

    memset(nonce, 'Q', sizeof(nonce));
    rc = MARS_Quote(/*regsel*/1<<0, nonce, sizeof(nonce), /*AK ctx*/"", /*ctxlen*/0, sig);
    CHECKRC
    hexout("SIG", sig, sizeof(sig));

    MARS_dump();
    MARS_DpDerive(0, "XYZZY", 5);
    MARS_dump();

    rc = MARS_Quote(/*regsel*/1<<0, nonce, sizeof(nonce), /*AK ctx*/"", /*ctxlen*/0, sig);
    CHECKRC
    hexout("SIG", sig, sizeof(sig));

// To verify a quote, the snapshot has to be reproduced
    // CryptSnapshot(snapshot, 1<<0, nonce, sizeof(nonce));
    MARS_SequenceHash();
    outlen = 0;
    MARS_SequenceUpdate("\x00\x00\x00\x01", 4, 0, &outlen);
    MARS_SequenceUpdate(dig, sizeof(dig), 0, &outlen);
    MARS_SequenceUpdate(nonce, sizeof(nonce), 0, &outlen);
    outlen = sizeof(dig);
    MARS_SequenceComplete(dig, &outlen);
    hexout("SS", dig, outlen);

    rc = MARS_SignatureVerify(/*restricted*/1, /*AK ctx*/"", /*ctxlen*/0,
        dig, sig, &flag);
    CHECKRC

    printf("Verify %s\n", flag ? "True" : "False");

    MARS_Derive(1, "CompoundDeviceID", 16, id);
    hexout("CDI2", id, sizeof(id));
    MARS_DpDerive(0, 0, 0);
    MARS_Derive(1, "CompoundDeviceID", 16, id);
    hexout("CDI1", id, sizeof(id));


    MARS_Unlock();
}
