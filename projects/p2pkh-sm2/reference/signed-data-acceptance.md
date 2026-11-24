# SM2 SignedData acceptance evidence

This fixture checks which envelopes the payment adapter accepts and verifies
general v2 signatures against trusted signer keys. The payment profile uses
one direct signature over the approved transaction message. Both entry
points enforce outer `SignedData.version = 1` and inner `SignerInfo.version = 2`.
The general verifier requires one or more signers and supports both direct
and signed-attribute signatures. [GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)

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
signer test as passed to count as end-to-end evidence. It replays attached
ForkID and detached Chronicle OTDA spends through BSV Node and chain-gang.

## Complete enumeration of the declared domain

| Axis | Values exercised |
| --- | --- |
| Encoded `SignerInfo.version` | 1, 2, 3 |
| Encoded `SignedData.version` | 1, 2 |
| Encapsulated content | Detached, approved message, different message |
| Signature algorithm identifier | SM2-1, SM2-with-SM3, SM3 |
| Authorization | Direct, signed attributes, different key, different SM2 user ID, different signed message |

The domain has \(3 \times 2 \times 3 \times 3 \times 5 = 270\)
tuples. On each run the fixture checks that the axes have distinct values,
every visited tuple belongs to the domain, each tuple is visited at most
once, and exactly 270 tuples were visited. A subset of a finite set with the
same cardinality equals the whole set. These assertions therefore detect a
missing, repeated, or unexpected row.

The fixture specifies the two accepted tuples explicitly. They are the
attached and detached forms of the valid version pair and a direct SM2-1
signature. An accepted row must return the exact raw signature decoded
independently from OpenSSL's output. The other 268 rows
must raise `ValueError`. This checks both false acceptance and false rejection
within the declared domain.

## Complete enumeration of optional metadata combinations

The second matrix holds the payment signature valid and crosses both
content modes with four states for each of
`certificates`, `crls` and `unsignedAttrs`. The states are absent, empty set,
one valid member and one member encoded as ASN.1 `NULL`. The same membership,
uniqueness and cardinality checks establish coverage of all
\(2 \times 4^3 = 128\) tuples.

The acceptance set follows from the field grammar. Certificates and CRLs
permit absent, empty and valid, while the optional unsigned attribute set
must have at least one attribute when present. Thus
\(2 \times 3 \times 3 \times 2 = 36\) tuples must yield the exact
payment signature. The other 92 must report the first invalid field.
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
| §8 table 2 `version` and table 3 `version` | Both entry points accept the same valid payment envelope. Two independently tested variants alter exactly one octet, setting inner version to 1 or outer version to 2. Both entry points reject each variant with the corresponding version error. The matrix crosses the encoded versions with content and signature cases. |
| §8 table 2 `digestAlgorithms` and table 3 `digestAlgorithm` | The fixture crosses SM3 and unkeyed SM3 with absent or DER NULL parameters in both fields. Wrong OIDs, keyed SM3, malformed NULL and a missing identifier are tested individually. The payment profile also rejects two entries that each pass as the sole SM3 entry. This isolates the payment cardinality rule. |
| §8 table 2 `encapContentInfo` | Matrix covers attachment, detachment and a different message. A different content type is rejected by the payment profile. |
| §6.6 and §8 table 3 `issuerAndSerialNumber` | Pinned identifier in positive cases. Wrong identifier, SKI and malformed configured serial numbers are rejected. A matching pinned and encoded identifier with ASN.1 `NULL` in the issuer RDN position also fails, along with empty RDN and malformed attribute cases. |
| §8 table 2 `signerInfos` | Payment fixtures reject zero signers, accept one and reject two. The general verifier accepts two trusted OpenSSL signers in attached and detached modes, including a mixed direct and signed-attribute envelope. A wrong SM2 user ID on the second signature or an absent trusted key fails the envelope. |
| §8 table 3 `signedAttrs` and signing rules after table 3 | OpenSSL verifies independently signed attribute sets with both matching and mismatching `messageDigest`. The general verifier requires exactly one digest attribute with one OCTET STRING matching the SM3 of the original content. Signed fixtures cover missing, duplicated, mistyped, truncated and mismatching digests, a wrong DER signing tag and unsorted attributes. The payment policy rejects attribute signatures. |
| §8 table 3 `signatureAlgorithm` and `signature` | Crossed algorithm and signature modes. Separate cases exercise missing, non-canonical and out-of-range signature integers in both scalar positions. |
| §8 table 2 `certificates` and `crls`, table 3 `unsignedAttrs` | Both content modes cross all declared member states. Separate regressions reject empty issuers, zero and overlong certificate serial numbers, CRLs without `nextUpdate`, and malformed BOOLEAN and INTEGER values. Controls include the maximum valid 20-octet certificate serial and canonical signed integers. |
| GB/T 20518-2018 §§5.2.3.3 and 5.3.3.2, certificate and CRL signature algorithms | Both entry points accept intact OpenSSL metadata. With the original signed body and signature value preserved, they reject replacing the outer algorithm OID or changing only its parameters. |
| X.690 §§8.6.2, 8.19, 10.2 and 11.2.1, open attribute values | Seventeen encodings exercise BIT STRING padding and primitive tags, OID termination and minimal encoding, and primitive OCTET STRING. Each appears as a direct or nested value and runs through payment `unsignedAttrs` and general `unsignedAttrs` and `signedAttrs`. OpenSSL independently verifies every signed-attribute signature. |

The unittest module adds an executable traceability check after the fixture
tests. The registry lists each field of §8 tables 2 and 3 and the required
witnesses for that field and the signature input rules. Each witness records execution
after asserting its expected outcomes. The final check requires exact
equality between the required and observed witness sets, and between the
declared table fields and the registry's table entries.

The single-octet version test fails in both entry points when either shared
version check is weakened to accept the mutated envelope.

Each of seven in-memory mutations caused its targeted fixture to fail.
The mutations bypassed certificate issuer and serial-width checks, CRL
`nextUpdate`, open-value INTEGER encoding, content-digest comparison,
second-signer verification and rejection of extra algorithm parameters.

With `cryptography` 43.0.0, the new certificate, CRL and attribute fixtures
caught 68 incorrect acceptances on the pre-fix implementation. All these
cases pass with the fix. Six independent mutations removed the matching
algorithm check or one of the BIT STRING, OBJECT IDENTIFIER and OCTET STRING
checks, and each mutation failed its targeted assertions.

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
of nonempty NULL, other parameter tags and repeated parameters. Embedded SM2
certificates and CRLs require absent parameters in their own signature
algorithm identifiers under GB/T 20518-2018. [GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[GB/T 33560-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=9BF813CEEAFB58A19534FF861465D8FD)

## Regression checks from the review of `4bcc9d5`

`SignedDataReview` runs 108 conforming controls and 120 rejection cases
for the encoding matrix below.
Each rejection test requires every case to raise `ValueError` and reports
any case that returns the valid payment signature or content. Fixture setup
checks the OpenSSL signatures and runs every case before these assertions.
The control test checks the number of cases and requires every conforming
sample to pass.

| Rule | Rejection cases |
| --- | --- |
| GB/T 20518-2018 §§5.2.2 and 5.3.2 | Four checks for explicit NULL in both SM2 signature algorithm identifiers of a certificate or CRL. Both verification entry points also accept controls with omitted parameters. |
| GB/T 20518-2018 §§5.2.2 and 5.3.2 and GB/T 35276 §7.3 | Twelve checks reject an incorrect signature tag, a zero scalar or a non-octet-aligned BIT STRING in the embedded signature value of an SM2 certificate or CRL. |
| GB/T 20518-2018 §§5.2.3.5.2 and 5.3.3.4–5.3.3.5 | Eight checks replace one 2049 time at a time with GeneralizedTime, covering certificate `notBefore` and `notAfter` and CRL `thisUpdate` and `nextUpdate`. Controls encode both fields as UTCTime in 2049 and GeneralizedTime in 2050. |
| X.690 §§8.4, 8.9–8.12, 8.20, 8.23, 10.2 and 11.7–11.8 | Ninety-six checks cover primitive SEQUENCE and SET, constructed strings, UTF-8 and character repertoires, RELATIVE-OID, ENUMERATED and DER time forms. Each case runs as a direct and nested value through payment `unsignedAttrs` and general `unsignedAttrs` and `signedAttrs`. |

The earlier 72-case rejection fixture reproduced incorrect acceptance of
all its negative cases on `3197dd9`, while its 60 controls passed. A separate OpenSSL replay
constructed 57 checks without the fixture helpers, including a mixed
2049/2050 validity interval, detached content, an RSA certificate with NULL
parameters, and independently signed attribute sets. The repaired
implementation matched every expected outcome.

## Additional Chapter 8 evidence

| Normative area | Evidence | Remaining scope |
| --- | --- | --- |
| GB/T 20518-2018 §§5.2.2, 5.2.4.1 and 5.3.2 | Both verification entry points exercise certificate v1, v2 and v3, CRL v1 and v2, and version restrictions for unique identifiers and extensions. Certificate, CRL and revoked-entry extensions are checked for unique OIDs, DER DEFAULT omission, exactly one wrapped DER value and the supported extension payload type. | Extension-specific rules are tracked below. |
| GB/T 35275-2026 §6.9 and §8 | Schema-aware verification checks a declared open type in both attribute fields. An independent signature remains valid when an inner SET OF is unsorted or the value has the wrong type. The ASN.1 schema check rejects both cases and identifies missing schemas explicitly. The format verifier applies the same declared DER type check to extension values. | Private attribute and extension OIDs require their declaring ASN.1 schemas and profile constraints. |
| GB/T 35275-2026 §8 signer-set grammar | Format validation accepts empty `SignerInfos` with attached, empty-attached and detached content and an empty or populated digest set. A wrong tag fails the format check. Signer verification covers one and multiple signers with mixed direct and attribute signing and requires at least one authenticated signature. | Covered for the declared framing and cardinality cases. |
| GB/T 35275-2026 §§6.3–6.4 and §8 signed input | The envelope fixture enumerates 32 combinations of the two digest OIDs and absent or NULL parameters at all three algorithm fields. Format validation and both signature entry points execute every row. Independent OpenSSL signatures exercise universal SET and context-specific signedAttrs preimages in both content modes. Matching settings accept each signature, and cross-verification rejects it. | The cited algorithm identifiers and Appendix A.1 give interoperability evidence. Envelope parameter syntax and the signed-attribute tagging convention still need a normative disposition for full conformance. |

The v2 certificate structural test uses `asn1crypto` because
`cryptography` rejects certificate version v2 at load time. The
validation runs on the original certificate bytes. Certificate path
validation, trust anchors, and revocation decisions belong to the caller.
An independent OpenSSL replay exercised 74 checks with its own DER
construction, including a v2 certificate with a unique identifier, valid
and duplicate private extensions, CRL version dependencies, and open
values with DER time and RELATIVE-OID encodings.

### Format and X.509 profile witnesses

`validate_signed_data_format` shares parsing with the signature verifier
and applies the following self-contained embedded-certificate and CRL
profile rules. Certificate signatures, certificate paths and revocation
decisions require trusted inputs at the application layer.

| Rule | Executable evidence |
| --- | --- |
| GB/T 20518-2018 §§5.2.3.6, 5.2.4.2.9 and 5.2.4.2.12 | An empty subject requires a critical, nonempty SAN. A CA requires a nonempty subject and critical basicConstraints. Encoding the default `cA FALSE` explicitly fails DER validation. |
| GB/T 20518-2018 §§5.2.4.2.2–5.2.4.2.4 and 5.2.4.2.13 | AKI and SKI are noncritical when present. A CA requires SKI and keyCertSign. keyCertSign and nameConstraints require a CA certificate. |
| GB/T 20518-2018 §5.2.4.2.8 | A policy mapping can map two ordinary OIDs. Both positions reject anyPolicy. |
| GB/T 20518-2018 §§5.3.4.1–5.3.4.5 | CRL AKI and cRLNumber are noncritical, issuerAltName is nonempty, and deltaCRLIndicator and issuingDistributionPoint are critical. Both number fields accept nonnegative DER integers of at most 20 content octets. |
| GB/T 20518-2018 §§5.3.4.6–5.3.4.7 | freshestCRL belongs on complete CRLs, is noncritical, contains at least one distribution point and omits reasons and cRLIssuer. Reason and invalidity date are noncritical, removeFromCRL requires a delta CRL, and certificateIssuer has at least one name. Revoked-entry serial numbers must be positive and fit within 20 DER content octets. |
| GB/T 20518-2018 §5.2.4.1 | A declared private ASN.1 type is checked for certificates, CRLs and revoked entries. Tests exercise valid types, invalid type and SET OF order, and a distinct missing-schema error. |

Remaining X.509 scope includes other extension-specific rules, issuer
and subject relationships, and revocation of certificates in the path. The
certificate fixture uses independently signed metadata to isolate each
rejection from the signature bytes.
The independent OpenSSL replay now runs 103 checks using a separate DER
constructor. Added cases include a private extension schema, removeFromCRL,
and crossed `signedAttrs` preimages.

The following witnesses add 80 OpenSSL-signed certificate or CRL cases.
Each object is signed and verified independently before it is embedded in a
zero-signer envelope for `validate_signed_data_format`. The zero-signer
envelope isolates metadata validation from content signature verification.

| Normative area | Cases | Executable evidence |
| --- | ---: | --- |
| GB/T 20518-2018 §§5.2.4.2.8, 5.2.4.2.13–14 | 27 | CA-only placement for policy mappings and name and policy constraints. Both subtree fields check nonempty sequences and omission of minimum and maximum. Both policy counters check zero, the DER sign-octet boundary, negative and nonminimal encodings. |
| GB/T 20518-2018 §§5.2.4.2.9–10, 5.2.4.2.15, 5.2.4.2.17 and 5.2.4.3.2–3 | 19 | Empty SAN entries are rejected even alongside a valid DNS name. Issuer alternative names, certificate distribution points, certificate freshestCRL and both information-access extensions have a nonempty list. Information-access extensions are noncritical. The other tested extensions permit both criticality settings. |
| GB/T 20518-2018 §§5.2.4.2.19–22 | 16 | The four defined OIDs each accept a noncritical PrintableString without a caller-supplied schema. Criticality, a different string type and an out-of-repertoire character each cause a distinct rejection. |
| GB/T 20518-2018 §§5.3.3.3, 5.3.3.6 and 5.3.4.5 with ITU-T X.690 §11.5 | 18 | CRL issuer RDN structure, omission of an empty revokedCertificates list, DER revocation time, and each implicit DEFAULT FALSE flag in issuingDistributionPoint. The flag fixtures independently exercise canonical TRUE, explicit FALSE and a noncanonical TRUE octet. |

[GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[ITU-T X.690](https://www.itu.int/rec/T-REC-X.690/en)

### Complete and delta CRL relationships

An individual delta CRL requires a `cRLNumber` greater than its
`BaseCRLNumber`. A caller can validate issuance metadata across an
authenticated series or check whether a complete CRL can serve as the
input for a given delta CRL. An envelope can carry a delta CRL while the
complete CRL is available from another source. The caller selects the
series and establishes issuer identity before comparing its metadata.

| Normative area | Executable evidence |
| --- | --- |
| GB/T 20518-2018 §§5.3.4.3–4 and RFC 5280 §5.2.3 | The profile rejects a missing delta number and numbers below or equal to the base. The series fixture independently crosses both CRL roles, the three issue-time orderings and the three number orderings in 36 rows, each run in both input orders. A three-object case checks a repeated number in an unsorted series. |
| RFC 5280 §5.2.4 | The pair fixture crosses the five positions of the complete number around BaseCRLNumber and the delta number with three issue-time positions in 15 rows. It also checks role reversals, differing issuers, and both absent, both equal, one absent and unequal issuing distribution points. |
| RFC 5280 §§7.1, 7.3 | The pair fixture exercises UTF8String and PrintableString comparison, insignificant space and case folding, domain-component case, and differing RDN attribute multiplicity. The distribution point scope is compared by its canonical DER value. |

The fixtures use OpenSSL to sign and verify both CRLs before invoking the
metadata verifier. The issuer-certificate path and publication of the
referenced complete CRL require separate evidence.
[GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[RFC 5280 §5.2.4](https://www.rfc-editor.org/rfc/rfc5280#section-5.2.4) ·
[RFC 5280 §7.1](https://www.rfc-editor.org/rfc/rfc5280#section-7.1)

### Revocation snapshot and same-time publication

`merge_crl_revocations` checks the pair and compares authority key
identifiers. It indexes each CRL by certificate issuer and serial, applies
delta entries over the complete list, and removes entries marked
`removeFromCRL`. The snapshot uses the delta CRL's number, times and scope.
For an indirect CRL, the first entry defaults to the CRL issuer and later
entries inherit the previous issuer unless a critical `certificateIssuer`
selects a new one. An application supplies an authenticated selection when
that extension contains multiple distinct directory names. Duplicate
issuer/serial entries and unsupported critical extensions fail the merge.

| Normative area | Executable evidence |
| --- | --- |
| RFC 5280 §§5.2.4 and 6.3.3(i)–(k) | A 20-row matrix crosses four complete-list states with five delta actions. It checks additions, replacements, retention, releases including an absent target, explicit or default unspecified reason, UTC dates and metadata inherited from the delta. |
| RFC 5280 §§5.3.3 and 6.3.3(c) | Direct and indirect entry witnesses check per-list issuer inheritance, issuer changes, equal serials at different issuers, criticality and missing or ambiguous DNs. Authority key identifiers agree or both are absent. A different or one-sided identifier fails the merge. |
| GB/T 20518-2018 §5.3.4.3 and RFC 5280 §5.2.3 | The optional same-time complete CRL must match the merged issuer/serial state, including reason and dates. Tests exercise an order-independent match and isolate a missing entry, extra entry, differing reason or dates, wrong number, time, issuer, scope and delta in the complete slot. |
| Independent OpenSSL check | Six test certificates produce 18 CLI verdicts using the complete CRL alone, the pair with `-extended_crl -use_deltas`, and the simultaneous complete CRL. The pair and simultaneous complete verdicts match the snapshot, and the base-only controls distinguish absent and released entries. |

The snapshot represents one scope at the delta's issue time. The
assessment described below combines snapshots for a target certificate.
[RFC 5280 §5.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.3) ·
[RFC 5280 §6.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3)

### CRL signer authentication

`verify_crl_signature` and the `issuer_certificate` option of
`merge_crl_revocations` bind each CRL to a caller-authenticated issuer
certificate. The merger verifies the complete, delta, and optional
same-time complete inputs with the same certificate key before applying
any revocation entry. For SM2, the verifier uses the certificate's
uncompressed curveSM2 key, the original `tbsCertList` octets, the DER
signature value, and the caller's configured signer ID. The RSA fixture
checks the platform signature verification path independently with OpenSSL.

| Normative area | Executable evidence |
| --- | --- |
| RFC 5280 §6.3.3(f)–(h) | The signed tests vary the key with the subject and serial fixed, change the issuer DN with the key fixed, and check keyUsage with cRLSign set, clear or absent. Independent counterexamples target each of the complete, delta and optional publication positions. |
| GB/T 20518-2018 §§5.3.2 and 5.3.4.1 | The fixtures vary the key identifier, the authority certificate issuer and the serial independently. The verifier compares a key identifier to a certificate SKI when both are present and tests each of the two authority identifier forms. The CRL signature is checked even when identifiers are absent. |
| GB/T 35276-2017 §§8.1–8.2 | OpenSSL signs and verifies with both a standard-length and an application-specific SM2 ID. The implementation rejects a wrong or unavailable ID, a different curve and an edited `tbsCertList`. |

The relying party supplies the authorized scope. The signer ID is an
explicit configuration input. Certificate paths can be checked during
assessment under a caller-selected trust anchor.
[GB/T 20518-2018](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F7B410A1B0C06206E5FFB0FBFEE82C75) ·
[RFC 5280 §6.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3)

### Certificate revocation scope and time

`assess_certificate_revocation` combines caller-selected authenticated
snapshots from complete CRLs or merged CRLs. The result is `revoked`,
`unrevoked` or `undetermined`, together with reason coverage. A valid
revocation entry determines `revoked`. An absent entry yields
`unrevoked` only when the usable snapshots cover all eight reasons.

| Normative area | Executable evidence |
| --- | --- |
| RFC 5280 §6.3.3(a) | Fixtures cover an inclusive `thisUpdate`, an exclusive `nextUpdate`, future and expired lists, release after an older hold, conflicting revisions and an entry dated after the assessment time. The latest available issue for a scope controls freshness. |
| RFC 5280 §6.3.3(b) and issuer fallback | Positive and negative witnesses vary direct and delegated issuer names, the indirect flag, IDP matching, full and relative names, the fallback issuer point, and CA, end-entity and attribute-certificate scopes. |
| RFC 5280 §§6.3.2 and 6.3.3(d)–(l) | Fixtures vary certificate and CRL reason masks independently, combine complementary scopes or distribution points, and distinguish partial coverage from a conclusive result. A future-dated entry or reason contradicting its CRL's mask prevents that snapshot from contributing coverage for the entry. |
| OpenSSL comparison | CLI fixtures check five cases for matching and mismatched scope, revocation, a future CRL and an expired CRL. The six existing base/delta certificate outcomes also exercise the assessment against independently verified CLI results. |

The caller supplies the applicable CRLs, any authenticated indirect issuer
selection and a validation time. The complete-only snapshot loader uses
numbered CRLs. Distribution name matching normalizes directory names and
compares other forms using their decoded values.
[RFC 5280 §6.3.2](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.2) ·
[RFC 5280 §6.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3)

### Pinned certificate paths for revocation assessment

Pass `trust_anchor` and any untrusted DER `intermediates` to
`assess_certificate_revocation`. OpenSSL validates the target chain and
the chain for each distinct certificate that authenticated a CRL snapshot,
at the requested time and with a trust store containing only the explicit
anchor. The target uses generic path validation and the CRL signer uses
the CRL-signing purpose. Path policy processing starts with `anyPolicy`.
A caller can also pin an intermediate as its
trust anchor. Path rejection aborts the assessment.

| Normative area | Executable evidence |
| --- | --- |
| RFC 5280 §6.1 | The fixtures exercise a missing intermediate, a modified certificate signature, certificate validity, name constraints, maximum path length, CA key usage, an unrecognized critical extension and explicit policy constraints. Positive controls exercise permitted names and matching explicit policies. |
| RFC 5280 §6.3.3(f) | A delegated RSA CRL signer and its target validate under one anchor. A root with the same subject and a different key, a signer rooted elsewhere, and an unrelated root presented as an intermediate are rejected. A separate OpenSSL-issued SM2 chain exercises the target and the CRL signer under one anchor and rejects a missing SM2 intermediate. |

Path verification uses the local OpenSSL certificate signature behavior.
The CRL signer ID controls CRL signature verification. The caller supplies
the available CRLs and verification time. Revocation of intermediate and
CRL signer certificates requires separate evidence.
[RFC 5280 §6.1](https://www.rfc-editor.org/rfc/rfc5280#section-6.1) ·
[RFC 5280 §6.3.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3)

The national standard catalog and the published texts were rechecked for
the two signature-encoding questions. The GB/T 33560 identifier assignments
and the explicit NULLs in the Appendix A.1 envelope provide OID and
interoperability evidence. The X.690 rule for IMPLICIT describes how to
encode the tagged field. RFC 5652 §5.4 separately specifies the universal
SET tag when producing the CMS signing input. GB/T 35275-2026 §8 names
the DER encoding of `signedAttrs`, and Appendix A.1 supplies a direct
signature. The acceptance record keeps the parameter and signing-tag
questions open pending an authoritative disposition for this standard.
The published drafting explanation also leaves these choices open. The
two questions are which parameter encodings each SignedData algorithm OID
permits, and whether §8 signs the DER field tagged `[0]` or its universal
SET encoding. The verifier has separate settings for the two preimages,
and the payment adapter continues to verify direct signatures over content.
[GB/T 35275-2026](https://std.samr.gov.cn/gb/search/gbDetailedCNF?id=511EBC5968889318E06397BE0A0AFBD5) ·
[GB/T 35275 drafting explanation](https://std.samr.gov.cn/dcpspTools/gbPlan/download?path=%2Fzxd%2F2024005089%2F20_%E6%A0%87%E5%87%86%E8%B5%B7%E8%8D%89%2F20_DI_2024005089_%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E6%8A%80%E6%9C%AF+SM2%E5%AF%86%E7%A0%81%E7%AE%97%E6%B3%95%E5%8A%A0%E5%AF%86%E7%AD%BE%E5%90%8D%E6%B6%88%E6%81%AF.pdf) ·
[GB/T 33560-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=9BF813CEEAFB58A19534FF861465D8FD) ·
[ITU-T X.690 §8.14](https://www.itu.int/rec/T-REC-X.690/en) ·
[RFC 5652 §5.4](https://www.rfc-editor.org/rfc/rfc5652#section-5.4)

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
provides a historical interoperability witness. The fixture confirms that
both signature algorithm identifiers of the embedded certificate contain
explicit DER NULL. The standalone version test checks the normative version
rule with a separate, valid v2 payment envelope.
[Hexadecimal transcription](https://www.gm7.org/archives/108338)
