#include "mars.h"
#include <string.h> // for memset()

#include <stdio.h>
void hexout(const char *msg, const void *buf, uint16_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}


main()
{
MARS_RC rc;
bool flag = 0;
size_t outlen = 0;
uint16_t diglen, siglen, keylen;

    _MARS_Init();
    MARS_Lock();

    MARS_CapabilityGet(MARS_PT_LEN_DIGEST, &diglen, sizeof(diglen));
    MARS_CapabilityGet(MARS_PT_LEN_SIGN, &siglen, sizeof(siglen));
    MARS_CapabilityGet(MARS_PT_LEN_SKEY, &keylen, sizeof(keylen));

uint8_t dig[diglen];
uint8_t sig[siglen];
uint8_t id[keylen];
uint8_t nonce[diglen];
uint8_t snapshot[diglen];

    char msg1[] = "this is a test";
    MARS_SequenceHash();
    MARS_SequenceUpdate(msg1, sizeof(msg1)-1, 0, &outlen);
    MARS_SequenceComplete(dig, &outlen);

    hexout("dig", dig, sizeof(dig));

    MARS_DpDerive(0, 0, 0);     // initialize (reset) the DP

    MARS_PcrExtend(0, dig);
    MARS_RegRead(0, dig);
    hexout("PCR0", dig, sizeof(dig));

    // CryptSnapshot(dig, 1, "ABCDE", 5);
    MARS_Derive(1, "CompoundDeviceID", 16, id);
    hexout("CDI", id, sizeof(id));

    memset(nonce, 'Q', sizeof(nonce));
    hexout("NONCE", nonce, sizeof(nonce));
    rc = MARS_Quote(/*regsel*/1<<0, nonce, sizeof(nonce), /*AK ctx*/"", /*ctxlen*/0, sig);
    printf("rc = %d\n", rc);
    hexout("SIG", sig, sizeof(sig));

// To verify a quote, the snapshot has to be reproduced
// CryptSnapshot is not part of the API, so would normally be implemented
// in SW without MARS.
    CryptSnapshot(snapshot, 1<<0, nonce, sizeof(nonce));

    MARS_SignatureVerify(/*restricted*/1, /*AK ctx*/"", /*ctxlen*/0,
        snapshot, sig, &flag);

    printf("Verify %s\n", flag ? "True" : "False");

    MARS_DpDerive(0, "XYZZY", 5);

    MARS_Unlock();
}

