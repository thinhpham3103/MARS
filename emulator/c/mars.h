#include <stdint.h> // for uint32_t, etc.
#include <stdlib.h> // for size_t
#include <stdbool.h> // for bool, true, false

#define MARS_PT_PCR	1	// uint16_t number of consecutive PCRs implemented on this MARS
#define MARS_PT_TSR	2	// uint16_t	number of consecutive TSRs implemented on this MARS
#define MARS_PT_LEN_DIGEST	3	// uint16_t	size of a digest that can be processed or produced
#define MARS_PT_LEN_SIGN	4	// uint16_t	size of signature produced by CryptSign()
#define MARS_PT_LEN_KSYM	5	// uint16_t	size of symmetric key produced by CryptSkdf()
#define MARS_PT_LEN_KPUB	6	// uint16_t	size of asymmetric key returned by MARS_PublicRead()
#define MARS_PT_LEN_KPRV	7	// uint16_t	size of private asymmetric key produced by CryptAkdf()
#define MARS_PT_ALG_HASH	8	// uint16_t	TCG-registered algorithm for hashing by CryptHash()
#define MARS_PT_ALG_SIGN	9	// uint16_t	TCG-registered algorithm for signing by CryptSign()
#define MARS_PT_ALG_SKDF	10	// uint16_t	TCG-registered algorithm for symmetric key derivation by CryptSkdf()
#define MARS_PT_ALG_AKDF	11	// uint16_t	TCG-registered algorithm for asymmetric key derivation by CryptAkdf()

#define MARS_RC_SUCCESS	0	// Command executed as expected
#define MARS_RC_FAILURE	1	// self-testing placed MARS in failure mode or MARS is otherwise inaccessible
#define MARS_RC_LOCK	2	// MARS is not locked
#define MARS_RC_BUFFER	3	// Invalid buffer pointer (null or misaligned) or length
#define MARS_RC_COMMAND	4	// Command not supported
#define MARS_RC_VALUE	5	// Value out of range or incorrect for context 
#define MARS_RC_REG	6	// Invalid register index specified
#define MARS_RC_SEQ	7	// Not preceded by Sequence start command

typedef uint16_t MARS_RC;

// MANAGEMENT

MARS_RC MARS_SelfTest (bool fullTest);
MARS_RC MARS_Lock ();
MARS_RC MARS_Unlock ();

MARS_RC MARS_CapabilityGet (
    uint16_t pt,
    void * cap,
    uint16_t caplen);

// SEQUENCE PRIMITIVES

MARS_RC MARS_SequenceHash ();

MARS_RC MARS_SequenceUpdate(
    const void * in,
    size_t inSize,
    void * out,
    size_t * outlen);

MARS_RC MARS_SequenceComplete(
    void * out,
    size_t * outlen);

// INTEGRITY COLLECTION

MARS_RC MARS_PcrExtend (
    uint16_t pcrIndex,
    const void * dig);

MARS_RC MARS_RegRead (
    uint16_t regIndex,
    void * dig);

// KEY MANAGEMENT

MARS_RC MARS_Derive (
    uint32_t regSelect,
    const void * ctx,
    uint16_t ctxlen,
    void * out);

MARS_RC MARS_DpDerive (
    uint32_t regSelect,
    const void * ctx,
    uint16_t ctxlen);

MARS_RC MARS_PublicRead (
    bool restricted,
    const void * ctx,
    uint16_t ctxlen,
    void * pub);

// ATTESTATION

MARS_RC MARS_Quote (
    uint32_t regSelect,
    const void * nonce,
    uint16_t nlen,
    const void * ctx,
    uint16_t ctxlen,
    void * sig);

MARS_RC MARS_Sign (
    const void * ctx,
    uint16_t ctxlen,
    const void * dig,
    void * sig);

MARS_RC MARS_SignatureVerify (
    bool restricted,
    const void * ctx,
    uint16_t ctxlen,
    const void * dig,
    const void * sig,
    bool * result);

