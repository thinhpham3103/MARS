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
int err;
unsigned int cmdcode;
unsigned int pt, index;
size_t bslen, bslen2;   // byte string length
bool fullTest;
uint16_t cap;
// sizeof(uint32_t) > sizeof(int) ??
unsigned int regsel; // type required by cbor

    if (cbor_value_get_int (it, &cmdcode)
                || cbor_value_advance_fixed(it))
        rc = MARS_RC_BUFFER;
    else if (failure && (cmdcode != MARS_CC_CapabilityGet)) {
        rc = MARS_RC_FAILURE;
    }
    else switch (cmdcode) {
        case MARS_CC_SelfTest:
        if (cbor_value_get_boolean (it, &fullTest))
            rc = MARS_RC_BUFFER;
        else
            rc = MARS_SelfTest(fullTest);
        cbor_encode_int(enc, rc);
        break;

        case MARS_CC_CapabilityGet: // assumes cap is uint16_t or int
        if (cbor_value_get_int (it, &pt))
            rc = MARS_RC_BUFFER;
        else
            rc = MARS_CapabilityGet (pt, &cap, sizeof(cap));
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_int(enc, cap);
        break;

        case MARS_CC_SequenceHash:
        rc = MARS_SequenceHash();
        cbor_encode_int(enc, rc);
        break;

        case MARS_CC_SequenceUpdate:
        if ( !cbor_value_is_byte_string(it)
                || cbor_value_calculate_string_length (it, &bslen)
                || (bslen > 100))
            rc = MARS_RC_BUFFER;
        else {
            uint8_t buf[bslen];
            uint16_t outlen = 0;
            cbor_value_copy_byte_string (it, buf, &bslen, it);
            rc = MARS_SequenceUpdate(buf, bslen, 0, &outlen);
        }
        cbor_encode_int(enc, rc);
        // hash has no output here, but other seqs might
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, 0, 0);
        break;

        case MARS_CC_SequenceComplete: // assumes seq is hash
        bslen = sizeof(dig);
        rc = MARS_SequenceComplete(dig, &bslen);
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, dig, bslen);
        break;

        case MARS_CC_PcrExtend:
        if (cbor_value_get_int (it, &index)
                || cbor_value_advance_fixed(it))
            rc = MARS_RC_REG;
        else if (!cbor_value_is_byte_string(it)
                || cbor_value_calculate_string_length (it, &bslen)
                || (bslen != PROFILE_LEN_DIGEST))
            rc = MARS_RC_BUFFER;
        else {
            uint8_t buf[bslen];
            cbor_value_copy_byte_string (it, buf, &bslen, it);
            rc = MARS_PcrExtend(index, buf);
        }
        cbor_encode_int(enc, rc);
        break;

        case MARS_CC_RegRead:
        if (cbor_value_get_int (it, &index)
                || cbor_value_advance_fixed(it))
            rc = MARS_RC_REG;
        else
            rc = MARS_RegRead(index, dig);
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, dig, PROFILE_LEN_DIGEST);
        break;

        case MARS_CC_Derive:
        if (cbor_value_get_int (it, &regsel)
                || cbor_value_advance_fixed(it))
            rc = MARS_RC_REG;
        else if (!cbor_value_is_byte_string(it)
                || cbor_value_calculate_string_length (it, &bslen)
                || (bslen > 100)) // TODO: max length
            rc = MARS_RC_BUFFER;
        else {
            uint8_t ctx[bslen];
            cbor_value_copy_byte_string (it, ctx, &bslen, it);
            rc = MARS_Derive(regsel, ctx, bslen, key);
        }
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, key, PROFILE_LEN_KSYM);
        break;

        case MARS_CC_DpDerive:
        if (cbor_value_get_int (it, &regsel)
                || cbor_value_advance_fixed(it))
            rc = MARS_RC_REG;
        else if (!cbor_value_is_byte_string(it)
                || cbor_value_calculate_string_length (it, &bslen)
                || (bslen > 100)) // TODO: max length
            rc = MARS_RC_BUFFER;
        else {
            uint8_t ctx[bslen];
            cbor_value_copy_byte_string (it, ctx, &bslen, it);
            rc = MARS_DpDerive(regsel, ctx, bslen);
        }
        cbor_encode_int(enc, rc);
        break;

        case MARS_CC_PublicRead: // TODO
        cbor_encode_int(enc, MARS_RC_COMMAND);
        break;

        case MARS_CC_Quote:
        if (cbor_value_get_int (it, &regsel)
                || cbor_value_advance_fixed(it))
            rc = MARS_RC_REG;
        else if (!cbor_value_is_byte_string(it)
                || cbor_value_calculate_string_length (it, &bslen2)
                || (bslen2 > 100)) // TODO: max length
            rc = MARS_RC_BUFFER;
        else {
            uint8_t nonce[bslen2];
            cbor_value_copy_byte_string (it, nonce, &bslen2, it);
            if (!cbor_value_is_byte_string(it)
                    || cbor_value_calculate_string_length (it, &bslen)
                    || (bslen > 100)) // TODO: max length
                rc = MARS_RC_BUFFER;
            else {
                uint8_t ctx[bslen];
                cbor_value_copy_byte_string (it, ctx, &bslen, it);
                rc = MARS_Quote(regsel, nonce, bslen2, ctx, bslen, sig);
            }
        }
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, sig, PROFILE_LEN_SIGN);
        break;

        case MARS_CC_Sign:
        if (!cbor_value_is_byte_string(it)
                || cbor_value_calculate_string_length (it, &bslen)
                || (bslen > 100)) // TODO: max length
            rc = MARS_RC_BUFFER;
        else {
            uint8_t ctx[bslen];
            cbor_value_copy_byte_string (it, ctx, &bslen, it);
            if (!cbor_value_is_byte_string(it)
                    || cbor_value_calculate_string_length (it, &bslen2)
                    || (bslen2 != PROFILE_LEN_DIGEST))
                rc = MARS_RC_BUFFER;
            else {
                cbor_value_copy_byte_string (it, dig, &bslen2, it);
                rc = MARS_Sign(ctx, bslen, dig, sig);
            }
        }
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_byte_string(enc, sig, PROFILE_LEN_SIGN);
        break;

        bool restricted, result;
        case MARS_CC_SignatureVerify: // ( restricted, ctx, ctxlen, dig, sig )
        // extract restricted, ctxlen (bslen)
        if (cbor_value_get_boolean (it, &restricted)
                || cbor_value_advance_fixed(it)
                || !cbor_value_is_byte_string(it)
                || cbor_value_calculate_string_length (it, &bslen)
                || (bslen > 100)) // TODO: max length
            rc = MARS_RC_BUFFER;
        else {
            // extract ctx, dig, sig
            uint8_t ctx[bslen];
            cbor_value_copy_byte_string (it, ctx, &bslen, it);
            if (!cbor_value_is_byte_string(it)
                    || (bslen2 = PROFILE_LEN_DIGEST, cbor_value_copy_byte_string (it, dig, &bslen2, it))
                    || (bslen2 != PROFILE_LEN_DIGEST)
                    || !cbor_value_is_byte_string(it)
                    || (bslen2 = PROFILE_LEN_SIGN, cbor_value_copy_byte_string (it, sig, &bslen2, it))
                    || (bslen2 != PROFILE_LEN_SIGN))
                rc = MARS_RC_BUFFER;
            else
                rc = MARS_SignatureVerify(restricted, ctx, bslen, dig, sig, &result);
        }
        cbor_encode_int(enc, rc);
        if (rc == MARS_RC_SUCCESS)
            cbor_encode_boolean(enc, result);
        break;

        default:
        cbor_encode_int(enc, MARS_RC_COMMAND);
    }
}


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

    // between step1 and step2, add parameters to array

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
    size_t bslen = sizeof(sig);
    cbor_value_copy_byte_string(&it, sig, &bslen, 0);
    hexout("SIG", sig, bslen);

    step1(MARS_CC_SignatureVerify); // (restricted, ctx, ctxlen, dig, sig, result)
    cbor_encode_boolean(&array, false);
    cbor_encode_byte_string(&array, "context", 7);
    cbor_encode_byte_string(&array, dig, sizeof(dig));
    cbor_encode_byte_string(&array, sig, sizeof(sig));
    step2();

}
