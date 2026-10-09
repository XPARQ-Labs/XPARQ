Public verification cases extracted from NIST ACVP-Server `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json`:
https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json

Source SHA-256: a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792

Only external Pure SHAKE s cases are included. `.pk`, `.message`, `.context`, `.signature` contain decoded bytes, no secret keys. Case IDs: [('128s', '128s-true', 342, True), ('128s', '128s-false', 337, False), ('192s', '192s-true', 368, True), ('192s', '192s-false', 365, False), ('256s', '256s-true', 399, True), ('256s', '256s-false', 393, False)]
The backend is tested with the vector context; protocol authorization always uses empty context. Keygen vectors in `slhdsa.rs` are from NIST's corresponding keyGen internalProjection, SHA-256: d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920

Audit signing known answers: external Pure deterministic sigGen cases [('128s', 25, 215, 0), ('192s', 27, 237, 0), ('256s', 29, 256, 0)]. `.sk` files are public NIST test keys, never wallet secrets. Source: https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json
Source SHA-256: 62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba
