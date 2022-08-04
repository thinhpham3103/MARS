#include <stdint.h>
#include <stdlib.h>
#include "mars_encoder_types.h"
#include "mars_decoder_types.h"
#include "mars_encoder.h"
#include "mars_decoder.h"

#include "mars.h"

// Extract MARS command and parameters from CBOR blob,
// call the selected MARS_ command, and marshall the results
// back over blob.
void dispatcher(void *inblob, size_t inlen, void *outblob, size_t *outlen_p)
{
    struct mars_command_ command;
    size_t len_out;
    struct mars_response response;
    uint8_t dig[PROFILE_LEN_DIGEST];
    uint8_t key[PROFILE_LEN_KSYM];
    uint8_t sig[PROFILE_LEN_SIGN];
    uint8_t ctx[PROFILE_LEN_DIGEST];

    if (cbor_decode_mars_command(inblob, inlen, &command, &len_out) != ZCBOR_SUCCESS)
        return;
    switch (command._mars_command_choice)
    {
    case _mars_command__SelfTest:
        response._mars_response_rc._MARS_RC_choice = MARS_SelfTest(command._mars_command__SelfTest._SelfTest_full_test);
        break;
    case _mars_command__CapabilityGet:
        response._mars_response_rc._MARS_RC_choice =
            MARS_CapabilityGet(command._mars_command__CapabilityGet._CapabilityGet_capability_choice,
                               &response._mars_response_data._mars_response_data__CapabilityGet_Rsp,
                               sizeof(response._mars_response_data._mars_response_data__CapabilityGet_Rsp));
        if (response._mars_response_rc._MARS_RC_choice == _MARS_RC__RC_SUCCESS)
            response._mars_response_data_present = 1;
        break;
    case _mars_command__SequenceHash:
        break;
    case _mars_command__SequenceUpdate:
        break;

    case _mars_command__SequenceComplete:
        break;

    case _mars_command__PcrExtend:
        break;

    case _mars_command__RegRead:
        // zcbor_bstr_encode_ptr
        break;
    case _mars_command__Derive:
        break;
    case _mars_command__DpDerive:
        break;
    case _mars_command__PublicRead:
        break;
    case _mars_command__Quote:
        break;

    case _mars_command__Sign:
        break;
    case _mars_command__SignatureVerify:
        break;
    }

    cbor_encode_mars_response(outblob, *outlen_p, &response, outlen_p);
}