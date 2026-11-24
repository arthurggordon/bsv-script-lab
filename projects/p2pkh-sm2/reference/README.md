# P2PKH-SM2 reference

Run from this directory. Python 3.12+, OpenSSL with SM2/SM3, and `ecdsa==0.19.1` are sufficient for local tests:

```sh
python3 -m pip install ecdsa==0.19.1
python3 -m unittest -v test_sm2
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format hex
```

`sm2.py` defines curve parameters, ZA, digest verification and an **explicit-nonce test-only** signer. `sm3_script.py` unrolls SM3 into ordinary Script bytecode. `asm/` contains SM2 group verification, scalar multiplication and PUSHTX. `p2pkh_sm2.py` is the wallet API. No new consensus opcode is used.

The local evaluator is a development harness. For independent complete-input validation, use Linux x86-64 with Rust, install the pinned extension, then run the mode suite and the node comparison:

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest -v test_sighash
bash verify.sh
```

This checks three consecutive transfers, mixed inputs and multiple outputs, output/input mutations, invalid keys/scalars/identities, forged signing preimages, and extra witness items in both BSV Node 1.2.3 and chain-gang. The node launcher checks the downloaded archive against the release checksum and uses a temporary regtest directory with no peers. It does not broadcast transactions.

`test_sm2.py` also checks SM3 padding boundaries and fixed-prefix midstates against the host SM3 implementation, the published SM2 vector, and a real OpenSSL-generated SM2 key/signature accepted by the generated script. All fixture private scalars and nonces are public test data.

### Chronicle conformance

The v2 zero-owner script is 199,777 bytes. Its SHA-256 is `2458fd154c157eec3ad4ddd9a2411baae23f53aef417c43e296653cf0e2b5ab9`. The [16 deterministic preimages](../template/sighash-modes.json) cover all paired modes and each unpaired SINGLE variant. The tests change other inputs, individual outputs, sequences and locktime after signing. They also validate a mixed BIP143/OTDA transaction and reproduce the v1 payment txid.

For this revision, the 112 complete-input coverage cases were run through both pinned chain-gang and the BSV Node 1.2.3 script interpreter, including six malformed preimages signed by the correct SM2 test key. The latter engine also ran 48 activation cases with explicit flags for pre-Chronicle spends, post-activation spends of older outputs, and post-activation spends of new outputs. To isolate activation from the transaction version, these 48 cases all used version 1. The Node result used a native macOS build of `VerifyScript` and `TransactionSignatureChecker` on serialized transactions and UTXO values. Use `bash verify.sh` to repeat the checks through Linux regtest RPC. The native result covers script validation only.

[BSV Node source](https://github.com/bitcoin-sv/bitcoin-sv/tree/6504a3aff65ba97c0f6c80962b033e35ecbfed4b) · [chain-gang source](https://github.com/linzhm/chain-gang/tree/5cb8c6e410dbfad1c619cec3ca54d1bcaacd4eb7) · [Chronicle release](https://docs.bsvblockchain.org/network-topology/nodes/sv-node/chronicle-release)

The [standard vector](../template/sm2-standard.json), [payment vector](../template/spend-all.json), and [layout manifest](../template/layout.json) are checked in. Raw lock bytes are generated on demand and checked against the pinned manifest hash.

## SignedData payment interop

[GB/T 35275-2026](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=28A18B702BDC318803E598F5E502E2CC)
specifies the SM2 signed message container. A configured provider can return
`SignedData` with the signature, algorithm identifiers, signer identifier and
optional content. The existing wallet callback accepts the raw 64-byte `r || s`
authorization. The adapter bridges these formats before the wallet builds the
input witness.

```python
from p2pkh_sm2 import sign_input
from signed_data import signed_data_signer

signer = signed_data_signer(provider, public_key, signer_identifier=pinned_der_issuer_and_serial)
signed_tx = sign_input(tx, input_index, funding_raw, public_key, signer, sighash_type)
```

`provider(message, user_id)` returns DER bytes. Pin the public key and complete
DER `IssuerAndSerialNumber` from trusted configuration. Section 8, tables 2
and 3 of GB/T 35275-2026 specify `SignedData.version = 1`,
`SignerInfo.version = 2`, the issuer-and-serial identifier, and the SM2-1
signature algorithm. Both verification entry points enforce these rules.
The payment adapter accepts both the SM3 OID and the unkeyed SM3 OID used
by Appendix A.1. The independent Go signer uses unkeyed SM3.
For these digest identifiers and the signature identifier, the adapter
accepts omitted parameters or an empty DER NULL. Appendix A.1 uses NULL
for the unkeyed SM3 and SM2-1 identifiers.

The payment adapter verifies one direct SM2 signature over the approved 32-byte payment
message with the pinned public key and the template's fixed SM2 user ID. If the
envelope includes content, its bytes must match the payment message. The
adapter checks the DER structure of embedded certificates, revocation lists
and unsigned attributes. It checks for a nonempty certificate issuer, a
positive certificate serial number encoded in at most 20 octets and a CRL
with a nextUpdate. Embedded metadata also has version and extension
structure checks. The configured public key determines payment
authorization. An application that uses PKI establishes certificate trust
separately.

With `signedAttrs`, the signer signs the DER attributes. Such a signature
requires a verifier for that signed payload. The payment adapter rejects it
because the current template verifies the transaction message directly.

The independent [Go signer](interop/go-signer/README.md) uses
`github.com/emmansun/gmsm@v0.45.4` for SM2/SM3 and Go's ASN.1 encoder to emit
complete DER envelopes from a separate process. Attached ForkID and detached
Chronicle OTDA payments pass through BSV Node and chain-gang. The suite also
checks an independent OpenSSL SM2 signature, rejects invalid envelopes and
verifies byte-for-byte witness equivalence with the raw-signature path.

The [SignedData acceptance fixture](signed-data-acceptance.md) exhausts its
270-row payment matrix and 128-row optional metadata matrix. It records the
historical Appendix A.1 replay and maps the tests to the standard's clauses.

## SignedData signature verification

Use `verify_signed_data` to verify v2 `SignerInfo` entries with trusted keys.
The mapping keys are complete DER issuer-and-serial identifiers. Each value
supplies the authenticated SM2 public key and user ID for that signer.

```python
from signed_data import verify_signed_data

content = verify_signed_data(envelope, {
    signer_a_id: (signer_a_public_key, signer_a_user_id),
    signer_b_id: (signer_b_public_key, signer_b_user_id),
}, detached_content=original_content)
```

Omit `detached_content` for an attached envelope. Verification requires at
least one signer and a valid signature from every listed signer. It handles
both direct signatures over the content octets and signatures over a DER
`SignedAttributes` SET. For a signer with attributes, it also checks that the
sole `messageDigest` value matches SM3 of the content octets. The caller
establishes signer trust and any certificate path or revocation policy.

For schema-aware `AttributeValue` validation, pass `attribute_schemas`, a
mapping from dotted attribute OIDs to `asn1crypto` ASN.1 classes. Each
declared value is decoded as its ASN.1 type and checked against the canonical
DER re-encoding. `messageDigest` has a built-in OCTET STRING check.
`MissingAttributeSchema` identifies an encountered OID whose schema is
unavailable. The configured schema defines the type and any application
constraints. [Acceptance evidence and remaining scope](signed-data-acceptance.md#additional-chapter-8-evidence)

Use `validate_signed_data_format(envelope, attribute_schemas=...)` for
Chapter 8 framing and the implemented X.509 extension profile checks.
This entry point can parse a certificate-only envelope with an empty
`SignerInfos` set, and it can parse a detached envelope without its content.
It returns normally when the format checks pass. Use `verify_signed_data`
with authenticated signer keys and any detached content to verify a
signature and obtain the signed bytes.

Pass `extension_schemas` to the format validator as a mapping from dotted
extension OIDs to `asn1crypto` ASN.1 classes. A supplied schema checks each
value against its canonical DER encoding. In this mode, an otherwise
unrecognized extension without a supplied schema raises
`MissingExtensionSchema`. The check applies to certificates, CRLs and
individual revoked-certificate entries.

Use `validate_crl_series(crls, extension_schemas=...)` to compare the
issuance numbers of DER CRLs for one authenticated issuer and scope. Use
`validate_crl_pair(complete_crl, delta_crl, extension_schemas=...)` to check
whether a numbered complete CRL meets the metadata requirements for
combining with a delta CRL. The caller authenticates both lists against
the same authorized signing key before relying on the pair check. Pass
objects from the envelope or from another authenticated source.

Use `merge_crl_revocations(complete_crl, delta_crl, published_crl=...)`
to build a snapshot for the delta CRL's number, validity times and
scope. Pass `issuer_certificate` as trusted DER to verify every supplied
CRL with that certificate's key, or authenticate the CRLs before calling.
Supply `sm2_user_id` as the configured signer ID when the CRL uses SM2.
`verify_crl_signature(crl, issuer_certificate, sm2_user_id=...)` provides
the same verification for one CRL. Establish the certificate path and
the issuer's authority for the CRL scope before using these checks.

Supply `published_crl` to compare with a complete CRL released at the
same `thisUpdate` and number. The snapshot's
`revocation_for(issuer_name, serial_number)` takes a `cryptography.x509.Name`
and returns the scoped revocation entry or `None` if absent. For an
indirect entry with multiple distinct directory names, an
`issuer_resolver(serial_number, candidates)` can select the authenticated
issuer name from the supplied candidates. Distribution-point applicability
and reason coverage can be evaluated with
`assess_certificate_revocation(certificate, snapshots, validation_time=...)`.
Build the snapshots with `load_crl_snapshot(crl, issuer_certificate, ...)`
for a numbered complete CRL or pass `issuer_certificate` when merging. For
the supplied timezone-aware time, the assessment returns `revoked`,
`unrevoked` when the available lists cover every reason, or `undetermined`
when coverage is insufficient. The caller supplies the available CRLs and
can pass `trust_anchor` and `intermediates` to the assessment to validate
the target and CRL signer paths under one explicitly trusted DER
certificate. This mode uses the local OpenSSL verifier with the supplied
validation time. The certificate signature uses OpenSSL's configured
algorithm behavior. `sm2_user_id` configures the separate CRL signature
check. Callers with independently validated paths can omit `trust_anchor`.

The general signature verifier takes `signed_attrs_encoding='cms-set'`
for the CMS universal SET signing input. Select `'context-field'` to
verify the original `[0]` field bytes. Each verification uses the selected
encoding. The acceptance record documents the evidence for both encodings
and the open normative question. [Encoding evidence](signed-data-acceptance.md#format-and-x509-profile-witnesses)
