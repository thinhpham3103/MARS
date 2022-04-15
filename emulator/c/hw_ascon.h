#include <stdint.h> // for uint32_t, etc.
#include <stdlib.h> // for size_t
#include <stdbool.h> // for bool, true, false

#define PROFILE_PCR_COUNT 4
#define PROFILE_TSR_COUNT 0

#include "../ascon/LibAscon-master/inc/ascon.h"

#define CryptHash ascon_hash
#define CryptHashInit ascon_hash_init
#define CryptHashUpdate ascon_hash_update
#define CryptHashFini ascon_hash_final
#define CryptXkdf CryptSkdf

#define PROFILE_DIGEST_LEN ASCON_HASH_DIGEST_LEN
#define PROFILE_SKEY_LEN   ASCON_AEAD128_KEY_LEN
#define PROFILE_XKEY_LEN   PROFILE_SKEY_LEN
#define PROFILE_SIG_LEN    ASCON_AEAD_TAG_MIN_SECURE_LEN
#define PROFILE_ALG_HASH   0x81
#define PROFILE_ALG_SIGN   0x82 // FIX - need TPM_ALG #s from TCG alg reg
#define PROFILE_ALG_SKDF   0x83

typedef ascon_hash_ctx_t profile_shc_t;

void CryptSkdf(void * key, const void * parent, char label, const void * ctx, uint16_t ctxlen);

bool CryptVerify(const void *key, const void *dig, const void *sig);

void CryptSign(void * out, const void * key, const void * digest);

