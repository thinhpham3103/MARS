#ifndef PROFILE_LEN_DIGEST
#  error preinclude profile header using: gcc -include profile.h
#endif

#include <string.h> // for memset()
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "mars.h"
#include "../tinycbor/src/cbor.h"

extern bool failure;

// cbor_vget() pulls multiple parameters from CBOR iterator
// 'b' is boolean
// 'w' is word (32-bit) integer
// 'h' is half word (16-bit) integer
// 'x' is byte string taking 2 parameters, buffer pointer and length pointer
// 'X' is byte string taking 2 parameters, buffer pointer and mandatory length
#include <stdarg.h>
CborError cbor_vget(CborValue *it, const char *ptype, ...)
{
    CborError err = CborNoError;
    va_list ap;
    size_t *zp, z2;
    unsigned int z;
    uint64_t i64;
    void *p;
#define va_get(Z) Z = va_arg(ap, typeof(Z))

    va_start(ap, ptype);
    while (!err && *ptype)      // walk through parameter types
        switch (*ptype++) {

        case 'b':               // boolean parameter
            va_get(p);
            err = cbor_value_is_boolean(it)
                ? cbor_value_get_boolean(it, p), cbor_value_advance_fixed(it)
                : CborUnknownError;
            break;

        case 'w':               // Word = uint32_t
            va_get(p);
            err = cbor_value_is_unsigned_integer(it)
                ? cbor_value_get_uint64(it, &i64),
                  cbor_value_advance_fixed(it)
                : CborUnknownError;
            if (!err)
                *(uint32_t *)p = i64; // truncate to 32 bits, TODO check if (i64>>32)
            break;

        case 'h':               // Half word = uint16_t
            va_get(p);
            err = cbor_value_is_unsigned_integer(it)
                ? cbor_value_get_uint64(it, &i64),
                  cbor_value_advance_fixed(it)
                : CborUnknownError;
            if (!err)
                *(uint16_t *)p = i64; // truncate to 16 bits, TODO check if (i64>>16)
            break;

        case 'x':               // byte string parameter
            va_get(p);          // pointer to buffer
            va_get(zp);         // pointer to length, in/out
            err = cbor_value_is_byte_string(it)
                ? cbor_value_copy_byte_string (it, p, zp, it)
                : CborUnknownError;
            if (err)
                *zp = 0;
            break;

        case 'X':               // byte string parameter
            va_get(p);          // pointer to buffer
            va_get(z);          // mandatory length
            err = (cbor_value_is_byte_string(it)
                    && (cbor_value_calculate_string_length (it, &z2), z==z2))
                ? cbor_value_copy_byte_string (it, p, &z2, it)
                : CborUnknownError;
            if (err)
                *zp = 0;
            break;

        default:
            err = CborUnknownError;
        }
    va_end(ap);
    if (err) printf("VGET err %d on '%c'\n", err, ptype[-1]);
    return err;
}


// Extract MARS command and parameters from CBOR blob,
// call the selected MARS_ command, and marshall the results
// back over blob.
void dispatcher(void *inblob, size_t inlen, void *outblob, size_t *outlen_p)
{
MARS_RC rc;
CborParser parser;
CborValue it;
CborEncoder enc, array;
uint8_t dig[PROFILE_LEN_DIGEST];    // TODO: consolidate the variables to reuse "hw" registers
uint8_t key[PROFILE_LEN_KSYM];
uint8_t sig[PROFILE_LEN_SIGN];
uint8_t ctx[PROFILE_LEN_DIGEST];
int err;
uint16_t cmdcode, pt, index;
uint32_t regsel;
size_t xlen1, xlen2, xlen3;     // general-purpose byte string lengths
bool fullTest;
uint16_t cap;

    // start parsing the input request, and get the cmdcode
    if (cbor_parser_init(inblob, inlen, 0, &parser, &it)
            || cbor_value_enter_container(&it, &it)
            || cbor_vget(&it, "h", &cmdcode))
        exit(5); // TODO reply MARS_RC_IO?

    // prepare an output encoder w/ array for response
    cbor_encoder_init(&enc, outblob, *outlen_p, 0);
    cbor_encoder_create_array(&enc, &array, CborIndefiniteLength);

    if (failure && (cmdcode != MARS_CC_CapabilityGet))
        rc = MARS_RC_FAILURE;
    else switch (cmdcode) {

        case MARS_CC_SelfTest:
        rc = cbor_vget (&it, "b", &fullTest)
            ? MARS_RC_IO
            : MARS_SelfTest(fullTest);
        cbor_encode_int(&array, rc);
        break;

        case MARS_CC_CapabilityGet: // assumes cap is uint16_t or int
        rc = cbor_vget (&it, "h", &pt)
            ? MARS_RC_IO
            : MARS_CapabilityGet (pt, &cap, sizeof(cap));
        cbor_encode_int(&array, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_int(&array, cap);
        break;

        case MARS_CC_SequenceHash:
        rc = MARS_SequenceHash();
        cbor_encode_int(&array, rc);
        break;

        case MARS_CC_SequenceUpdate:
        // it'd be more efficient to use the bytes from it in-place,
        // instead of copying to buf first
        if ( !cbor_value_is_byte_string(&it)
                || cbor_value_calculate_string_length (&it, &xlen1)
                || (xlen1 > 2048))
            rc = MARS_RC_IO;
        else {
            uint8_t buf[xlen1];
            uint16_t outlen = 0;
            cbor_value_copy_byte_string (&it, buf, &xlen1, &it);
            rc = MARS_SequenceUpdate(buf, xlen1, 0, &outlen);
        }
        cbor_encode_int(&array, rc);
        // hash has no output here, but other seqs might
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(&array, 0, 0);
        break;

        case MARS_CC_SequenceComplete: // assumes seq is hash
        xlen1 = sizeof(dig);
        rc = MARS_SequenceComplete(dig, &xlen1);
        cbor_encode_int(&array, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(&array, dig, xlen1);
        break;

        case MARS_CC_PcrExtend: // ( index, dig )
        xlen1 = sizeof(dig);
        if (cbor_vget(&it, "hx", &index, &dig, &xlen1))
            rc = MARS_RC_IO;
        else if (xlen1 != PROFILE_LEN_DIGEST)
            rc = MARS_RC_BUFFER;
        else
            rc = MARS_PcrExtend(index, dig);
        cbor_encode_int(&array, rc);
        break;

        case MARS_CC_RegRead: // ( index )
        rc = cbor_vget(&it, "h", &index)
            ? MARS_RC_IO
            : MARS_RegRead(index, dig);
        cbor_encode_int(&array, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(&array, dig, PROFILE_LEN_DIGEST);
        break;

        case MARS_CC_Derive: // (regSelect, ctx, ctxlen)
        xlen1 = sizeof(ctx);
        rc = cbor_vget(&it, "wx", &regsel, &ctx, &xlen1)
            ? MARS_RC_IO
            : MARS_Derive(regsel, ctx, xlen1, key);
        cbor_encode_int(&array, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(&array, key, PROFILE_LEN_KSYM);
        break;

        case MARS_CC_DpDerive:
        xlen1 = sizeof(ctx);
        rc = cbor_vget(&it, "w", &regsel)
            ? MARS_RC_IO
            : cbor_value_is_null(&it)
                ? MARS_DpDerive(0, 0, 0)
                : cbor_vget(&it, "x", &ctx, &xlen1)
                    ? MARS_RC_IO
                    : MARS_DpDerive(regsel, ctx, xlen1);
        cbor_encode_int(&array, rc);
        break;

        case MARS_CC_PublicRead: // TODO
        cbor_encode_int(&array, MARS_RC_COMMAND);
        break;

        case MARS_CC_Quote: // ( regSelect, nonce, nlen, ctx, ctxlen, sig )
        xlen1 = sizeof(ctx);
        xlen2 = sizeof(dig);  // reuse dig to hold a nonce
        rc = cbor_vget(&it, "wxx", &regsel, &dig, &xlen2, &ctx, &xlen1)
            ? MARS_RC_IO
            : MARS_Quote(regsel, dig, xlen2, ctx, xlen1, sig);
        cbor_encode_int(&array, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(&array, sig, PROFILE_LEN_SIGN);
        break;

        case MARS_CC_Sign: // ( ctx, ctxlen, dig, sig )
        xlen1 = sizeof(ctx);
        xlen2 = sizeof(dig);
        if (cbor_vget(&it, "xx", &ctx, &xlen1, &dig, &xlen2))
            rc = MARS_RC_IO;
        else if (xlen2 != PROFILE_LEN_DIGEST)
            rc = MARS_RC_BUFFER;
        else
            rc = MARS_Sign(ctx, xlen1, dig, sig);
        cbor_encode_int(&array, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(&array, sig, PROFILE_LEN_SIGN);
        break;

        bool restricted, result;
        case MARS_CC_SignatureVerify: // ( restricted, ctx, ctxlen, dig, sig )
        xlen1 = sizeof(ctx);
        xlen2 = sizeof(dig);
        xlen3 = sizeof(sig);
        if (cbor_vget(&it, "bxxx", &restricted, &ctx, &xlen1, &dig, &xlen2, &sig, &xlen3 ))
            rc = MARS_RC_IO;
        else if (xlen2 != PROFILE_LEN_DIGEST || xlen3 != PROFILE_LEN_SIGN)
            rc = MARS_RC_BUFFER;
        else
            rc = MARS_SignatureVerify(restricted, ctx, xlen1, dig, sig, &result);
        cbor_encode_int(&array, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_boolean(&array, result);
        break;

        default:
        cbor_encode_int(&array, MARS_RC_COMMAND);
    }
    // TODO check for failure mode, return MARS_RC_FAILURE
    // TODO check that IT is at end - no trailing parameters
    cbor_encoder_close_container(&enc, &array);
    *outlen_p = cbor_encoder_get_buffer_size(&enc, outblob);
}
