// Demo to show how MARS can produce a CDI needed for DICE applications

#include <stdio.h>
#include "mars.h"

static void hexout(const char *msg, const void *buf, size_t len)
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
size_t outlen = 0;
uint16_t diglen, keylen;

    _MARS_Init();
    MARS_Lock();

    MARS_CapabilityGet(MARS_PT_LEN_DIGEST, &diglen, sizeof(diglen));
    MARS_CapabilityGet(MARS_PT_LEN_KSYM, &keylen, sizeof(keylen));

uint8_t dig[diglen];
uint8_t cdi[keylen];  // Compound Device Identifier

    MARS_SequenceHash();
    MARS_SequenceUpdate("FIRST MUTABLE CODE", 18, 0, &outlen);
    MARS_SequenceComplete(&dig, &outlen);
    hexout("FMC ", &dig, sizeof(dig));

    MARS_PcrExtend(0, &dig);
    MARS_RegRead(0, &dig);
    hexout("PCR0", &dig, sizeof(dig));

    MARS_Derive(1<<0, "CompoundDeviceID", 16, &cdi);
    hexout("CDI ", &cdi, sizeof(cdi));
    rc = MARS_Unlock();
}

