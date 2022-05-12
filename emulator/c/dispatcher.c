#ifndef PROFILE_LEN_DIGEST
#  error preinclude profile header using: gcc -include profile.h
#endif

#include <string.h> // for memset()
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "mars.h"
#define MARS_RC_IO 99 // TODO add I/O or parsing RC
#include "../tinycbor/src/cbor.h"

extern bool failure;

#define CHECKRC if (rc) { printf("rc=%d, line=%d\n", rc, __LINE__); exit(rc); }

static void hexout(const char *msg, const void *buf, uint16_t len)
{
typeof(len) i;
    if (msg)
        printf("%s: ", msg);
    for (i=0; i<len; i++)
        printf("%02x", ((uint8_t *)buf)[i]);
    printf("\n");
}

// cbor_vget() pulls multiple parameters from CBOR iterator
#include <stdarg.h>
CborError cbor_vget(CborValue *it, const char *ptype, ...)
{
    va_list ap;
    bool *bp;   // boolean pointer
    uint8_t *xp; // byte string pointer
    int *ip;    // int pointer
    CborError err = CborNoError;
    size_t *zp;
#define va_get(Z) Z = va_arg(ap, typeof(Z))

    va_start(ap, ptype);
    while (!err && *ptype)      // walk through parameter types
        switch (*ptype++) {

        case 'b':               // boolean parameter
            va_get(bp);
            (   err = cbor_value_get_boolean (it, bp))
            || (err = cbor_value_advance_fixed(it));
            break;

        case 'x':               // byte string parameter
            va_get(xp);
            va_get(zp);
            err = cbor_value_is_byte_string(it)
                ? cbor_value_copy_byte_string (it, xp, zp, it)
                : CborUnknownError;
            if (err)
                *zp = 0;
            break;

        case 'i':               // int parameter
            va_get(ip);
            (   err = cbor_value_get_int (it, ip))
            || (err = cbor_value_advance_fixed(it));
            break;
        default:
            err = CborUnknownError;
        }
    va_end(ap);
    if (err) printf("VGET err %d\n", err);
    return err;
}


// Extract MARS command parameters from CBOR iterator "it",
// call the selected MARS_ command, and marshall the results
// to CBOR encoder "enc".
void dispatcher(CborValue *it, CborEncoder *enc)
{
MARS_RC rc;
uint8_t inblob[1024], outblob[1024];
uint8_t dig[PROFILE_LEN_DIGEST];    // TODO: consolidate the variables to reuse "hw" registers
uint8_t key[PROFILE_LEN_KSYM];
uint8_t sig[PROFILE_LEN_SIGN];
uint8_t ctx[PROFILE_LEN_DIGEST];
int err;
unsigned int cmdcode;
unsigned int pt, index;
size_t xlen1, xlen2, xlen3;   // byte string length
bool fullTest;
uint16_t cap;
// sizeof(uint32_t) > sizeof(int) ??
unsigned int regsel; // type required by cbor

    if (cbor_vget(it, "i", &cmdcode))
        rc = MARS_RC_IO;
    else if (failure && (cmdcode != MARS_CC_CapabilityGet))
        rc = MARS_RC_FAILURE;
    else switch (cmdcode) {

        case MARS_CC_SelfTest:
        rc = cbor_vget (it, "b", &fullTest)
            ? MARS_RC_IO
            : MARS_SelfTest(fullTest);
        cbor_encode_int(enc, rc);
        break;

        case MARS_CC_CapabilityGet: // assumes cap is uint16_t or int
        rc = cbor_vget (it, "i", &pt)
            ? MARS_RC_IO
            : MARS_CapabilityGet (pt, &cap, sizeof(cap));
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_int(enc, cap);
        break;

        case MARS_CC_SequenceHash:
        rc = MARS_SequenceHash();
        cbor_encode_int(enc, rc);
        break;

        case MARS_CC_SequenceUpdate:
        // it'd be more efficient to use the bytes from it in-place,
        // instead of copying to buf first
        if ( !cbor_value_is_byte_string(it)
                || cbor_value_calculate_string_length (it, &xlen1)
                || (xlen1 > 2048))
            rc = MARS_RC_IO;
        else {
            uint8_t buf[xlen1];
            uint16_t outlen = 0;
            cbor_value_copy_byte_string (it, buf, &xlen1, it);
            rc = MARS_SequenceUpdate(buf, xlen1, 0, &outlen);
        }
        cbor_encode_int(enc, rc);
        // hash has no output here, but other seqs might
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, 0, 0);
        break;

        case MARS_CC_SequenceComplete: // assumes seq is hash
        xlen1 = sizeof(dig);
        rc = MARS_SequenceComplete(dig, &xlen1);
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, dig, xlen1);
        break;

        case MARS_CC_PcrExtend: // ( index, dig )
        xlen1 = sizeof(dig);
        if (cbor_vget(it, "ix", &index, &dig, &xlen1))
            rc = MARS_RC_IO;
        else if (xlen1 != PROFILE_LEN_DIGEST)
            rc = MARS_RC_BUFFER;
        else
            rc = MARS_PcrExtend(index, dig);
        cbor_encode_int(enc, rc);
        break;

        case MARS_CC_RegRead: // ( index )
        rc = cbor_vget(it, "i", &index)
            ? MARS_RC_IO
            : MARS_RegRead(index, dig);
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, dig, PROFILE_LEN_DIGEST);
        break;

        case MARS_CC_Derive: // (regSelect, ctx, ctxlen)
        xlen1 = sizeof(ctx);
        rc = cbor_vget(it, "ix", &regsel, &ctx, &xlen1)
            ? MARS_RC_IO
            : MARS_Derive(regsel, ctx, xlen1, key);
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, key, PROFILE_LEN_KSYM);
        break;

        case MARS_CC_DpDerive:
        xlen1 = sizeof(ctx);
        rc = cbor_vget(it, "ix", &regsel, &ctx, &xlen1)
            ? MARS_RC_IO
            : MARS_DpDerive(regsel, ctx, xlen1);
        cbor_encode_int(enc, rc);
        break;

        case MARS_CC_PublicRead: // TODO
        cbor_encode_int(enc, MARS_RC_COMMAND);
        break;

        case MARS_CC_Quote: // ( regSelect, nonce, nlen, ctx, ctxlen, sig )
        xlen1 = sizeof(ctx);
        xlen2 = sizeof(dig);  // reuse dig to hold a nonce
        rc = cbor_vget(it, "ixx", &regsel, &dig, &xlen2, &ctx, &xlen1)
            ? MARS_RC_IO
            : MARS_Quote(regsel, dig, xlen2, ctx, xlen1, sig);
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, sig, PROFILE_LEN_SIGN);
        break;

        case MARS_CC_Sign: // ( ctx, ctxlen, dig, sig )
        xlen1 = sizeof(ctx);
        xlen2 = sizeof(dig);
        if (cbor_vget(it, "xx", &ctx, &xlen1, &dig, &xlen2))
            rc = MARS_RC_IO;
        else if (xlen2 != PROFILE_LEN_DIGEST)
            rc = MARS_RC_BUFFER;
        else
            rc = MARS_Sign(ctx, xlen1, dig, sig);
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, sig, PROFILE_LEN_SIGN);
        break;

        bool restricted, result;
        case MARS_CC_SignatureVerify: // ( restricted, ctx, ctxlen, dig, sig )
        xlen1 = sizeof(ctx);
        xlen2 = sizeof(dig);
        xlen3 = sizeof(sig);
        if (cbor_vget(it, "bxxx", &restricted, &ctx, &xlen1, &dig, &xlen2, &sig, &xlen3 ))
            rc = MARS_RC_IO;
        else if (xlen2 != PROFILE_LEN_DIGEST || xlen3 != PROFILE_LEN_SIGN)
            rc = MARS_RC_BUFFER;
        else
            rc = MARS_SignatureVerify(restricted, ctx, xlen1, dig, sig, &result);
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_boolean(enc, result);
        break;

        default:
        cbor_encode_int(enc, MARS_RC_COMMAND);
    }
}

// The following is used to demonstrate the dispatcher.
// Eventually, the dispatcher will be a stand-alone server.
// Until then, and until an API is made, commands are generated here.
main()
{
CborParser parser;
CborValue it;
CborEncoder in, out, array;
uint8_t inbuf[1024];
#if 0
uint8_t outbuf[1024];
#else // seems dangerous, but works w/ tinycbor
#define outbuf inbuf
#endif
uint16_t buflen;
int err;
unsigned int cc;
uint8_t dig[PROFILE_LEN_DIGEST];
uint8_t sig[PROFILE_LEN_SIGN];

#define chkerr if (err) printf("err %d %d\n", __LINE__, err)

    void step1( unsigned int cc)
        {
        // begin encoding a new request/command
        printf("\nCOMMAND %d\n", cc);
        cbor_encoder_init(&in, inbuf, sizeof(inbuf), 0);
        cbor_encoder_create_array(&in, &array, CborIndefiniteLength);
        cbor_encode_int(&array, cc);
        }

    // between using step1 and step2, add parameters to array

    void step2 ()
        {
        // finish encoding the incoming request
        cbor_encoder_close_container(&in, &array);
        buflen = cbor_encoder_get_buffer_size(&in, inbuf);

        // print the request raw and pretty
        hexout("REQUEST BLOB", inbuf, buflen);
        cbor_parser_init(inbuf, buflen, 0, &parser, &it);
        cbor_value_to_pretty_advance(stdout, &it);
        printf("\n");

        // start parsing the input request for the dispatcher
        if (cbor_parser_init(inbuf, buflen, 0, &parser, &it)
                || cbor_value_enter_container(&it, &it))
            exit(5); // reply?

        // prepare an output encoder w/ array for response
        cbor_encoder_init(&out, outbuf, sizeof(outbuf), 0);
        cbor_encoder_create_array(&out, &array, CborIndefiniteLength);

        // execute the command, and terminate the reply array
        dispatcher(&it, &array);
        // TODO check for failure mode, return MARS_RC_FAILURE
        // TODO check that IT is at end - no trailing parameters
        cbor_encoder_close_container(&out, &array);
        buflen = cbor_encoder_get_buffer_size(&out, outbuf);

        // print the response raw and pretty
        hexout("RESPONSE BLOB", outbuf, buflen);
        if (cbor_parser_init(outbuf, buflen, 0, &parser, &it))
            exit(6); // reply?
        cbor_value_to_pretty_advance(stdout, &it);
        printf("\n");
        }

    // The code below mimics demo.c
    // This should be replaced by code that uses an API over a marshalling layer.

    step1(MARS_CC_SelfTest);
    cbor_encode_boolean(&array, true);
    step2();

    step1(MARS_CC_CapabilityGet);
    cbor_encode_int(&array, MARS_PT_ALG_HASH);
    step2();

    step1(MARS_CC_SequenceHash);
    step2();

    step1(MARS_CC_SequenceUpdate);
    cbor_encode_byte_string(&array, "this is a test", 14);
    step2();

    step1(MARS_CC_SequenceComplete);
    step2();
    // reparse the response to get the resulting digest
    cbor_parser_init(outbuf, buflen, 0, &parser, &it);
    cbor_value_enter_container(&it, &it);
    cbor_value_advance_fixed(&it); // skip response code
    size_t diglen = sizeof(dig);
    cbor_value_copy_byte_string(&it, dig, &diglen, 0);
    hexout("DIG", dig, diglen);

    step1(MARS_CC_PcrExtend);
    cbor_encode_int(&array, 0);
    cbor_encode_byte_string(&array, dig, diglen);
    step2();

    step1(MARS_CC_RegRead);
    cbor_encode_int(&array, 0);
    step2();

    step1(MARS_CC_Derive);
    cbor_encode_int(&array, 1); // regSelect
    cbor_encode_byte_string(&array, "CompoundDeviceID", 16);
    step2();

    step1(MARS_CC_Quote);
    uint8_t nonce[PROFILE_LEN_DIGEST];
    memset(nonce, 'Q', sizeof(nonce));
    cbor_encode_int(&array, 1); // regSelect
    cbor_encode_byte_string(&array, nonce, sizeof(nonce));
    cbor_encode_byte_string(&array, 0, 0); // context
    step2();

    step1(MARS_CC_Sign);
    cbor_encode_byte_string(&array, "context", 7);
    cbor_encode_byte_string(&array, dig, sizeof(dig));
    step2();
    // reparse the response to get the resulting signature
    cbor_parser_init(outbuf, buflen, 0, &parser, &it);
    cbor_value_enter_container(&it, &it);
    cbor_value_advance_fixed(&it); // skip response code
    size_t xlen1 = sizeof(sig);
    cbor_value_copy_byte_string(&it, sig, &xlen1, 0);
    hexout("SIG", sig, xlen1);

    step1(MARS_CC_SignatureVerify); // (restricted, ctx, ctxlen, dig, sig, result)
    cbor_encode_boolean(&array, false);
    cbor_encode_byte_string(&array, "context", 7);
    cbor_encode_byte_string(&array, dig, sizeof(dig));
    cbor_encode_byte_string(&array, sig, sizeof(sig));
    step2();

}
