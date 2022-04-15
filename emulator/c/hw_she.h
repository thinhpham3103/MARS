#include <stdint.h> // for uint32_t, etc.
#include <stdlib.h> // for size_t
#include <stdbool.h> // for bool, true, false

#define PROFILE_PCR_COUNT 4
#define PROFILE_TSR_COUNT 0

#define PROFILE_DIGEST_LEN 16
#define PROFILE_SKEY_LEN 16
#define PROFILE_XKEY_LEN PROFILE_SKEY_LEN
#define PROFILE_SIG_LEN 16
#define PROFILE_ALG_HASH   0x84 // FIX - need TPM_ALG #s from TCG alg reg
#define PROFILE_ALG_SIGN   0x3F // TPM_ALG_CMAC ??
#define PROFILE_ALG_SKDF   0x86

#define CryptSelfTest SHE_selftest
#define CryptHash SHE_hash
#define CryptHashInit SHE_hash_init
#define CryptHashUpdate SHE_hash_update
#define CryptHashFini SHE_hash_fini
#define CryptSign SHE_cmac1
#define CryptVerify SHE_verify
#define CryptSkdf SHE_kdf
#define CryptXkdf CryptSkdf

// hctx is Hash ConTeXt
typedef struct {
    size_t   total;          // total # of source bytes hashed
    uint16_t part_n;         // number of bytes in partial block
    uint8_t  part_blk[32];   // includes room for extra block when padding
    uint8_t  H[16];          // running digest
} she_hctx_t;

typedef she_hctx_t profile_shc_t;   // for MARS' Sequenced Hash Context

void SHE_kdf(void * key, const void * parent, char label, const void * ctx, uint16_t ctxlen);

bool SHE_verify(const void *key, const void *dig, const void *sig);

void SHE_cmac1(uint8_t *mac, const uint8_t *key, const uint8_t *blk);

void SHE_hash_init(she_hctx_t * hctx);

// Hash blocks from previous partial block (if any) and msg
// Bytes from trailing incomplete block are copied to part_blk
void SHE_hash_update(she_hctx_t * hctx, const uint8_t * msg, size_t n);

// pad and do final compress, return digest
void SHE_hash_fini(she_hctx_t * hctx, void *dig);

void SHE_hash(void *out, const void * msg, size_t n);
