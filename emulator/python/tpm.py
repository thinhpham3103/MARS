#!/usr/bin/env python3

# Simple aid for verifying a MARS signature with TPM utilities.
# See ../tpm/.

key = bytes.fromhex('788dd25eb94736784e29dea2dbe1609e98176e6cb5372d3c59b8e2ea4b8080e2')

import hw_sha2 as hw
from mars import MARS_RoT

m = MARS_RoT(hw, key, 4, True)

m.Lock()
print('sig ', m.Quote(0, b'', b'AK1').hex())
# snapshot: df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
# signature 86d5ef6fce993580bcfffa7f6dde92df4cfac616676c4a4beca2f9d022dc460f

