// empty MARS implementation
// use LD_PRELOAD w/ actual implementation
#include <stdint.h> // for uint32_t, etc.

#define decl(x) uint16_t MARS_##x() { return 4; }
decl(dump)
decl(SelfTest)
decl(CapabilityGet)
decl(SequenceHash)
decl(SequenceUpdate)
decl(SequenceComplete)
decl(PcrExtend)
decl(RegRead)
decl(Derive)
decl(DpDerive)
decl(PublicRead)
decl(Quote)
decl(Sign)
decl(SignatureVerify)
