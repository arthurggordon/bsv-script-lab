# SM2 SignedData acceptance evidence

This fixture checks which envelopes the payment adapter accepts and verifies
general v2 signatures against trusted signer keys. The payment profile uses
one direct signature over the approved transaction message. Inner version 1
is an explicit payment compatibility profile. The general verification
entry point requires one or more signers and supports both direct and
signed-attribute signatures. [GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)

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
| §8 table 2 `digestAlgorithms` and table 3 `digestAlgorithm` | The fixture crosses SM3 and unkeyed SM3 with absent or DER NULL parameters in both fields. Wrong OIDs, keyed SM3, malformed NULL and a missing identifier are tested individually. The payment profile also rejects two entries that each pass as the sole SM3 entry. This isolates the payment cardinality rule. |
| §8 table 2 `encapContentInfo` | Matrix covers attachment, detachment and a different message. A different content type is rejected by the payment profile. |
| §6.6 and §8 table 3 `issuerAndSerialNumber` | Pinned identifier in positive cases. Wrong identifier, SKI and malformed configured serial numbers are rejected. A matching pinned and encoded identifier with ASN.1 `NULL` in the issuer RDN position also fails, along with empty RDN and malformed attribute cases. |
| §8 table 2 `signerInfos` | Payment fixtures reject zero signers, accept one and reject two. The general verifier accepts two trusted OpenSSL signers in attached and detached modes, including a mixed direct and signed-attribute envelope. A wrong SM2 user ID on the second signature or an absent trusted key fails the envelope. |
| §8 table 3 `signedAttrs` and signing rules after table 3 | OpenSSL verifies independently signed attribute sets with both matching and mismatching `messageDigest`. The general verifier requires exactly one digest attribute with one OCTET STRING matching the SM3 of the original content. Signed fixtures cover missing, duplicated, mistyped, truncated and mismatching digests, a wrong DER signing tag and unsorted attributes. The payment policy rejects attribute signatures. |
| §8 table 3 `signatureAlgorithm` and `signature` | Crossed algorithm and signature modes. Separate cases exercise missing, non-canonical and out-of-range signature integers in both scalar positions. |
| §8 table 2 `certificates` and `crls`, table 3 `unsignedAttrs` | Both versions and content modes cross all declared member states. Separate regressions reject empty issuers, zero and overlong certificate serial numbers, CRLs without `nextUpdate`, and malformed BOOLEAN and INTEGER values. Controls include the maximum valid 20-octet certificate serial and canonical signed integers. |

The unittest module adds an executable traceability check after the fixture
tests. The registry lists each field of §8 tables 2 and 3 and the required
witnesses for that field and the signature input rules. Each witness records execution
after asserting its expected outcomes. The final check requires exact
equality between the required and observed witness sets, and between the
declared table fields and the registry's table entries.

Each of seven in-memory mutations caused its targeted fixture to fail.
The mutations bypassed certificate issuer and serial-width checks, CRL
`nextUpdate`, open-value INTEGER encoding, content-digest comparison,
second-signer verification and rejection of extra algorithm parameters.

For signed attributes, the verifier uses the CMS `messageDigest` OID
1.2.840.113549.1.9.4 and the universal DER SET tag as the signing input.
Appendix A.1 is a direct-signature example. The OpenSSL fixtures sign the
attribute bytes independently and distinguish the SET signing input from the
envelope's implicit context tag. [RFC 5652 §§5.4 and 11.2](https://www.rfc-editor.org/rfc/rfc5652)

The completeness claim covers the two declared products and the explicit
prefix and suffix families. The other tests are targeted witnesses. More
schema-specific DER evidence would be needed for arbitrary open attribute
types and complete X.509 certificate and CRL profiles. Certificate path and
revocation policy are established externally. The verifier requires at
least one authenticated signature for acceptance. The ASN.1 `SignerInfos`
grammar also describes empty sets.

GB/T 35275-2026 §6 uses AlgorithmIdentifier. GB/T 20518-2018 §5.2.2
declares its parameters optional and leaves parameter syntax to the
algorithm. The GB/T 33560 identifier tables supply the SM3, unkeyed SM3
and SM2-1 OIDs. Appendix A.1 demonstrates explicit DER NULL for the
unkeyed SM3 and SM2-1 fields in the envelope. The envelope verification
profile accepts absent parameters or empty DER NULL and tests rejection
of nonempty NULL, other parameter tags and repeated parameters. The
certificate-specific rules for signature algorithm identifiers have their
own context. [GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[GB/T 33560-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=9BF813CEEAFB58A19534FF861465D8FD)

## Appendix A.1 audit

The published example shows two unkeyed SM3 identifiers
(`1.2.156.10197.1.401.1`) with DER NULL on printed pages 11 and 16.
The outer version is 1 and the embedded message is 24 bytes. The
example's inner version is 1 at offset 860 on printed page 15. Section 8
table 3 gives the normative inner version as 2.
[GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)

The fixture pins a published hexadecimal transcription of the version-1
example, checks the field offsets against the official listing, and replays
its signature in OpenSSL over the 24 embedded bytes using the certificate's
public key and the explicitly configured SM2 user ID. The valid signature
provides an interoperability witness. The version discrepancy and the
message length preclude use of the example as a strict v2 payment fixture.
For general verification the fixture also checks that v2 rejects the
original envelope and accepts a derivative with only the unsigned
`SignerInfo.version` octet changed to 2.
[Hexadecimal transcription](https://www.gm7.org/archives/108338)
