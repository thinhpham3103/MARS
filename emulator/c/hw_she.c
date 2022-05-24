// Sample Crypt primitives based on AES hash, CMAC and KDF for MARS
// Implements algorithms specified in AUTOSAR Secure Hardware Extensions (SHE)
// Author: Tom Brostrom

// AES implementation from:
// Tiny AES, https://github.com/kokke/tiny-AES-c

#include "../aes/aes.h" // Tiny AES

#include <string.h>   // for memset, memcpy
#include <stdio.h>
#include <stdbool.h>

#include "hw_she.h"

static void hexout(const char *msg, const void *buf, size_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}

// Left shift byte array by 1 bit
// Return the final carry bit
static uint8_t ls1(uint8_t *a, size_t n)
{
uint8_t C2, C = 0;

    while (n--)
        {
        C2 = a[n] >> 7;
        a[n] = (a[n] << 1) | C;
        C = C2;
        }
    return C;
}

// XOR Byte Arrays, x = x ^ y
static void xba(uint8_t * x, const uint8_t *y, size_t n)
{
    while (n--)
        x[n] ^= y[n];
}

// Simplified CMAC algorithm for a single block.
void SHE_cmac1(uint8_t *mac, const uint8_t *key, const uint8_t *blk)
{
struct AES_ctx ctx;

    AES_init_ctx(&ctx, key);
    memset(mac, 0, 16);
    AES_ECB_encrypt(&ctx, mac);
    if (ls1(mac,16))
        mac[15] ^= 0x87;
    xba(mac, blk, 16);
    AES_ECB_encrypt(&ctx, mac);
}

bool SHE_verify(const void *key, const void *dig, const void *sig)
{
uint8_t mac[16];
    SHE_cmac1(mac, key, dig);
    return memcmp(mac, sig, 16) == 0;
}

void SHE_kdf(void * key, const void * parent, char label, const void * ctx, uint16_t ctxlen)
{
she_hctx_t hctx;
    SHE_hash_init(&hctx);
    SHE_hash_update(&hctx, parent, 16);
    SHE_hash_update(&hctx, "\x01\x01", 2);
    SHE_hash_update(&hctx, &label, 1);
    SHE_hash_update(&hctx, ctx, ctxlen);
    SHE_hash_update(&hctx, "", 1);
    SHE_hash_fini(&hctx, key);
}


// Miyaguchi–Preneel (MP) compression
// https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi–Preneel
// Apply MP round to each block in message M
// Any trailing incomplete block is ignored
static void mp_comp(const uint8_t * M, size_t n, uint8_t * H)
{
size_t j, b = n >> 4;  // number of full blocks to process, n / 16
struct AES_ctx ctx;
uint8_t EkM[16];

    while (b--)
        {
        AES_init_ctx(&ctx, H);
        memcpy(&EkM, M, sizeof(EkM));
        AES_ECB_encrypt(&ctx, EkM);
        for (j=0; j<16; j++)
            H[j] ^= EkM[j] ^ M[j];
        M += 16;
        }
}

// msg is padded in-place
// returns size of padded msg
static size_t pad(uint8_t * msg, size_t n, size_t total)
{
size_t i, r, z;
    if (!total)
        total = n;
    r = n & 0xf;                    // remainder bytes in last block of msg
    z = (r<=10 ? 10 : 26) - r;      // z = number of 0 bytes pad
    msg += n;
    *msg++ = 0x80;
    memset(msg, 0, z);
    msg += z;
    total <<= 3;                    // total *= 8, number of bits
    for (i=5; i-->0; )
        *msg++ = total >> (i<<3);   // append total bits, big endian in 5 bytes
    return n + 1 + z + 5;
}

void SHE_hash_init(she_hctx_t * hctx)
{
    memset(&hctx->H, 0, 16);
    hctx->total = 0;
    hctx->part_n = 0;
}

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

// Hash blocks from previous partial block (if any) and msg
// Bytes from trailing incomplete block in msg are copied to part_blk
void SHE_hash_update(she_hctx_t * hctx, const uint8_t * msg, size_t n)
{
size_t pn;  // number of bytes to append to partial block
    hctx->total += n;
    if (hctx->part_n)   // any bytes from partial block?
        {               // try to fill part_blk from msg
        pn = MIN(16-hctx->part_n, n);
        memcpy(&hctx->part_blk[hctx->part_n], msg, pn);
        hctx->part_n += pn;
        msg += pn;
        n -= pn;
        if (hctx->part_n == 16)
            {           // part_blk is full, compress it
            mp_comp(hctx->part_blk, 16, hctx->H);
            hctx->part_n = 0;
            }
        }
     if (n)     // additional bytes in msg
        {       // part_n should be 0 at this point
        mp_comp(msg, n, hctx->H);
        pn = n & 0xf;   // n % 16, bytes from trailing partial block
        msg += n - pn;  // move trailing pn bytes to part_blk
        hctx->part_n = pn;
        memcpy(&hctx->part_blk, msg, pn);
        }
}

// pad and do final compress, return digest
void SHE_hash_fini(she_hctx_t * hctx, void *dig)
{
    hctx->part_n = pad(hctx->part_blk, hctx->part_n, hctx->total);
    mp_comp(hctx->part_blk, hctx->part_n, hctx->H);
    memcpy(dig, hctx->H, sizeof(hctx->H));
}

void SHE_hash(void *out, const void * msg, size_t n)
{
she_hctx_t hctx;
    SHE_hash_init(&hctx);
    SHE_hash_update(&hctx, msg, n);
    SHE_hash_fini(&hctx, out);
}

// These tests are from the AUTOSAR SHE spec, 4.13 Examples and Test Vectors
// See https://www.autosar.org/fileadmin/user_upload/standards/foundation/20-11/AUTOSAR_TR_SecureHardwareExtensions.pdf
bool SHE_selftest(bool fullTest)
{
size_t i;
uint8_t key[16], out[16];
uint8_t key1[16] =  { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t msg1[16] =  { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
uint8_t exp1[16] =  { 0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                      0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c };

uint8_t exp2[16] =  { 0x11, 0x8a, 0x46, 0x44, 0x7a, 0x77, 0x0d, 0x87,
                      0x82, 0x8a, 0x69, 0xc2, 0x22, 0xe2, 0xd1, 0x7e };

// TEST 1 for CMAC, from spec 4.13.2.3, example 1
    SHE_cmac1(out, key1, msg1);
    if (memcmp(out, exp1, 16) != 0)
        return false;

// TEST2 for KDF, from spec 4.13.2.5
    for (i=0; i<sizeof(key); i++)
        key[i] = i;
    SHE_kdf(out, key, 'S', "HE", 2);
    if (memcmp(out, exp2, 16) != 0)
        return false;

    return true;
}

