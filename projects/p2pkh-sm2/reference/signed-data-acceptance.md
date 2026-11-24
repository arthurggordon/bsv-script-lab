# SM2 SignedData acceptance evidence

This fixture checks which envelopes the payment adapter accepts. It also
exercises concrete differences between payment acceptance and GB/T 35275-2026
§8 conformance. The standard permits signatures over signed attributes and
multiple signers. The payment profile uses one direct signature over the
approved transaction message. Inner version 1 is a separate compatibility
profile. [GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)

## Run the acceptance fixture

Install the pinned [reference dependencies](requirements.txt). Run the finite
fixture with Python 3.12 and OpenSSL with SM2 and SM3 support. The fixture
generates dedicated test keys and checks signatures independently in OpenSSL.

From the repository root:

```sh
PYTHONPATH=.:projects/p2pkh-sm2/reference python -m unittest -v test_signed_data_acceptance
```

For BSV Node 1.2.3 replay, build the [independent Go signer](interop/go-signer/README.md).
Set `SM2_SIGNED_DATA_SIGNER` to its absolute executable path and run
`bash projects/p2pkh-sm2/reference/verify.sh`. The run must show the independent
signer test as passed to count as end-to-end evidence. It replays both configured
versions with attached ForkID and detached Chronicle OTDA spends through
BSV Node and chain-gang.

## Complete enumeration of the declared domain

| Axis | Values exercised |
| --- | --- |
| Configured signer version | 1, 2 |
| Encoded `SignerInfo.version` | 1, 2, 3 |
| Encoded `SignedData.version` | 1, 2 |
| Encapsulated content | Detached, approved message, different message |
| Signature algorithm identifier | SM2-1, SM2-with-SM3, SM3 |
| Authorization | Direct, signed attributes, different key, different SM2 user ID, different signed message |

The domain has \(2 \times 3 \times 2 \times 3 \times 3 \times 5 = 540\)
tuples. On each run the fixture checks that the axes have distinct values,
every visited tuple belongs to the domain, each tuple is visited at most
once, and exactly 540 tuples were visited. A subset of a finite set with the
same cardinality equals the whole set. These assertions therefore detect a
missing, repeated, or unexpected row.

The fixture specifies the six accepted tuples explicitly. They are the
attached and detached forms of the three allowed configured/encoded version
and algorithm combinations. An accepted row must return the exact raw
signature decoded independently from OpenSSL's output. The other 534 rows
must raise `ValueError`. This checks both false acceptance and false rejection
within the declared domain.

A mutation check in memory detected all five deliberately broken checks
covering configured version, attached content, SM2 verification, the v2
algorithm identifier, and minimal DER lengths. Removing one matrix row also
failed the run with a count of 539.

## Complete enumeration of optional metadata combinations

The second matrix holds the payment signature valid and crosses both
configured versions and both content modes with four states for each of
`certificates`, `crls` and `unsignedAttrs`. The states are absent, empty set,
one valid member and one member encoded as ASN.1 `NULL`. The same membership,
uniqueness and cardinality checks establish coverage of all
\(2 \times 2 \times 4^3 = 256\) tuples.

The acceptance set follows from the field grammar. Certificates and CRLs
permit absent, empty and valid, while the optional unsigned attribute set
must have at least one attribute when present. Thus
\(2 \times 2 \times 3 \times 3 \times 2 = 72\) tuples must yield the exact
payment signature. The other 184 must report the first invalid field.
OpenSSL independently generates and parses the test certificate and CRL.
Separate mutations cover a CRL placed in the certificate field, a certificate
placed in the CRL field, empty sequences presented as either type, and
invalid OID, tag, length and order in unsigned attributes.
Bypassing the validator for each optional field in turn made this matrix
fail in all three runs. Each original wrong-type counterexample therefore
checks the adapter's actual decision.

## Clause-to-test traceability

| Rule | Executable evidence |
| --- | --- |
| §5 outer `ContentInfo` | Correct content OID in every matrix row. Wrong OID, every proper prefix of a valid attached envelope, all 256 one-byte suffixes and targeted DER length violations are rejected. |
| §8 table 2 `version` and table 3 `version` | Matrix crosses configured, inner and outer versions. The v2 profile requires outer 1 and inner 2. |
| §8 table 2 `digestAlgorithms` and table 3 `digestAlgorithm` | SM3 in the accepted examples. Missing or substituted SM3 and an additional unsupported algorithm are exercised individually. |
| §8 table 2 `encapContentInfo` | Matrix covers attachment, detachment and a different message. A different content type is rejected by the payment profile. |
| §6.6 and §8 table 3 `issuerAndSerialNumber` | Pinned identifier in positive cases. Wrong identifier and SKI substitutions are rejected. The companion SignedData tests cover malformed configured serial numbers. |
| §8 table 2 `signerInfos` | One signer in the matrix. The two-signer fixture carries independently verified signatures and is rejected by the single-signer payment profile. |
| §8 table 3 `signedAttrs` and signing rules after table 3 | OpenSSL verifies the signature over the attribute SET and rejects the same signature over the raw payment message. The adapter rejects the attribute form. |
| §8 table 3 `signatureAlgorithm` and `signature` | Crossed algorithm and signature modes. Separate cases exercise missing, non-canonical and out-of-range signature integers in both scalar positions. |
| §8 table 2 `certificates` and `crls`, table 3 `unsignedAttrs` | Both versions and content modes cross all declared member states. Wrong-type values, including the three original ASN.1 `NULL` counterexamples, are rejected. Independent schema and order mutations exercise checks inside the wrappers. |

The completeness claim covers the two declared products and the explicit
prefix and suffix families. Full-envelope conformance would also need evidence
for other DER encodings, content OIDs, message and key values, nested open
attribute values, arbitrary signer sets, and signed attributes. Certificate
and revocation-list checks here use X.509 DER parsing. Trust and revocation
policy are established externally.
