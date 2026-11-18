# P2PKH-SM2 v1

Experimental specification · BRC number unassigned · [中文](spec.zh-CN.md)

## Payment and authorization

A payer creates an output from the recipient's HASH160 of a 65-byte uncompressed curveSM2 public key (`04 || X_BE32 || Y_BE32`). On spend, the owner reveals that key and provides one SM2 signature for the current input. The witness never includes a parent transaction or an earlier signature.

The program uses existing BSV Script opcodes. It computes SM3 and verifies SM2 in Script; native `OP_CHECKSIG` remains secp256k1 ECDSA and binds the supplied transaction preimage through the public PUSHTX construction. Only the SM2 private key is required from the owner.

## Exact signing semantics

The template fixes the SM2 identity to the 16 ASCII bytes `1234567812345678`, with ENTLA `0080` (bit length, big endian). All curve parameters and coordinates are 32-byte big endian values.

```text
ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Qx || Qy)
H  = SHA256(SHA256(P))
e  = SM3(ZA || H)
```

A standard SM2 message-sign API receives **H and IDA**. An explicitly prehashed SM2 API receives **e**. Do not hash e again through a message API. The script recomputes ZA and e; it does not accept either as a trusted witness. The first 128 bytes of the ZA input are fixed, so their SM3 midstate is a program constant. The remaining two ZA compression blocks and both message-hash blocks execute on chain.

The curve, public-key check and signature equation are those of SM2, not P-256 ECDSA. Reject malformed keys, coordinates outside `[0,p)`, points off curve, signature scalars outside `[1,n)`, `t=(r+s) mod n=0`, and an infinite `R=sG+tQ`. Require `r=(e+x(R)) mod n`. With projective coordinates, test the two possible x candidates `(r-e) mod n` and that value plus n (only when below p). The implementation relies on `p<2n`. No inverse witness is required. Do not apply ECDSA low-S normalization to SM2 signatures.

## Transaction scope and bytes

v1 fixes `SIGHASH_ALL | SIGHASH_FORKID` (`0x41`). It can authorize an input of a multi-input, multi-output transaction. The convenience payment API builds a single-input payment with one or more outputs. NONE, SINGLE, ANYONECANPAY and OTDA are outside this version.

The program ends with `OP_CODESEPARATOR OP_CHECKSIG`. The scriptCode is `ac`, serialized as `01ac`. P is exactly 158 bytes:

```text
versionLE32 || hashPrevouts || hashSequence || outpoint || 01ac ||
amountLE64 || sequenceLE32 || hashOutputs || locktimeLE32 || 41000000
```

The native check binds the owner's approved H to the actual current input, previous amount and transaction coverage. Its public signature construction is not an owner authorization by itself. The node obtains the previous amount and lock from the UTXO context; an earlier full transaction is only wallet-side evidence. This reference does not implement header-chain or Merkle-proof validation.

| Item | Encoding |
|---|---|
| Lock | 199,530 bytes |
| Owner slot | zero-based `[50,70)` |
| Witness item 1 | push(P), 160 serialized bytes |
| Witness item 2 | push(Q), 66 serialized bytes |
| Witness item 3 | push(r_BE32 || s_BE32), 65 serialized bytes |
| Complete scriptSig | 291 bytes, exactly three items |

Recognition checks all fixed program bytes. [The layout](../template/layout.json) pins the length, owner offset, zero-owner program hash and fixed-byte fingerprint. Generate raw bytes with [generate_lock.py](../reference/generate_lock.py). Expanded hex is deliberately reproducible rather than duplicated in source control.

## Integration

[The Python API](../reference/p2pkh_sm2.py) exports output generation from a hash or validated public key, full-template recognition, `current_input_unlock`, and `sign_payment`. The payment helper validates the funding output, key, outputs and explicit fee, calls `signer(H, IDA)`, verifies its returned raw signature and serializes the spend.

The caller authenticates the funding transaction and confirmation state and obtains approval of recipients, change and fees. Secret-key signing belongs in an external signer. The pure-Python arithmetic and explicit-nonce fixture signer are not constant-time production signing implementations. The identity string is an algorithm input; it is not identity certification or X.509 validation.

## Evidence and boundaries

Tests cover the published SM2 vector, OpenSSL signing, SM3 block boundaries and fixed-prefix hashing, invalid points and scalars, wrong identities, t=0, infinity, the rare x≥n branch, transaction/preimage substitution and three consecutive payments. Local opcode evaluation is a development harness without consensus flags or resource limits. [Complete-input tests](../reference/test_node.py) separately exercise BSV Node 1.2.3 and pinned chain-gang with explicit UTXOs and flags.

Successful regtest verification does not establish mainnet activation, relay policy, hardware integration or fee suitability. The large lock must be priced against actual miner policy. This is an experimental implementation, not cryptographic product certification.

Sources: [RFC 8998](https://www.rfc-editor.org/rfc/rfc8998.html#section-3.2.1), [OpenSSL standard vector](https://github.com/openssl/openssl/blob/openssl-3.5.0/test/sm2_internal_test.c), [SM3 Internet-Draft](https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3-02), [WP1605](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf) and [BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md). The a=−3 projective arithmetic/window structure and native public signature construction derive from this repository's [R1 project](../../p2pkh-r1/README.md), with independent SM2 constants and verification equation.
