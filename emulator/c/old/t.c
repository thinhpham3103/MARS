#include "../c/hw_she.h"
#include <stdio.h>

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
unsigned int i;
char buf[30];
char dig[PROFILE_LEN_DIGEST];
profile_shc_t shc;

    for (i=0; i<sizeof(buf); i++) {
        SHE_hash_init(&shc);
        SHE_hash_update(&shc, buf, i);
        SHE_hash_fini(&shc, dig);
        printf("%d ", i);
        hexout(0, dig, sizeof(dig));
        buf[i] = 'Z';
    }
}


