# Security boundaries and review notes

## What this experiment establishes

The primitive checks 256 SHA-256 preimages. The payment script additionally checks
a native current-input transaction relation. This is a research implementation;
passing tests is not a security audit or proof of end-to-end post-quantum security.
Python key handling does not offer secure memory erasure or hardware isolation.

## Fixed-r binding: analyze the relation, not the presence of CHECKSIG alone

Let G be the secp256k1 generator, n its order, r=x(G), Q=G and h=int(SHA256d(P)).
Script constructs, rather than accepts from the witness,

```
s0 = (h + r) mod n
s = min(s0, n - s0)
signature = strict-DER(r, s) || 0x41
```

It rejects s0=0. Both private key d=1 and nonce k=1 are public by design. This
native ECDSA signature is a transaction-binding gadget, not an owner signature;
Lamport alone supplies the owner's authorization.

For actual native transaction digest z, ECDSA tests the x-coordinate of
R' = ((z+r)/s)G modulo n. Here r+n exceeds the field prime p, so the only curve
points with x mod n=r are G and -G. Consequently acceptance requires

```
z = h (mod n), or z = -h - 2r (mod n).
```

This is a **small digest equivalence class, not literal 256-bit equality**.
Low-s normalization preserves this two-sign ambiguity. Reduction modulo n can
also admit an additional 256-bit representative. To redirect an observed valid
Lamport authorization to different transaction contents, an attacker still needs
a transaction preimage whose native hash hits one of those targets, or must break
Lamport authorization / the hash assumptions. Arbitrary valid ECDSA signatures
for Q do not help: the locking program computes its own fixed-r signature.

This algebra also explains why merely saying “CHECKSIG uses elliptic curves, so
Shor automatically breaks this gadget” is not a sufficient analysis: no unknown
discrete logarithm protects this fixed-key construction. Conversely, this note
is not a formal quantum security reduction. SHA-256 preimage/collision bounds,
chosen-message security, multiple targets, hash composition, one-time state and
consensus semantics all need review before deployment. A 256-bit digest is not a
claim of 256-bit quantum security.

The script checks preimage length, exact scriptCode and exact sighash bytes before
hashing. The final executed separator leaves only `ac` for native scriptCode.
Its DER signature and sighash byte cannot be chosen independently by the witness.
No detached, host-provided “CHECKSIG succeeded” result is accepted on chain.

## One-time means one disclosure, not one confirmed transaction

Never use a key for two messages, two inputs, two UTXOs, fee replacements, alternate
transactions, channels or retries that change the digest. Unconfirmed signatures
already disclose secrets. Backups and process restarts do not reset that fact.

`OneTimeSigner` consumes its secret reference before returning a signature and
uses a lock to prevent concurrent calls. Even an identical-digest retry is refused.
It cannot stop a copied secret or reconstructed signer. Durable key reservation,
crash recovery, anti-rollback storage, signer import/export, secure erasure and
broadcast persistence are deliberately not implemented. A wallet must persist
consumption before disclosure and store the signed transaction for rebroadcast.
A crash may sacrifice availability; it must not permit a second disclosure.

The payment helper rejects change to the same canonical key, but this is only a
local guard. Script cannot remember that the same public key appears elsewhere.
The tests deliberately show that two signatures on complementary raw digests
reveal all blocks and allow forgery for any third digest. This is a primitive-level
demonstration, not an assertion that real transaction hashes can be chosen freely.

## Detached digest verifier is intentionally unsafe as a payment lock

An attacker can copy its digest and signature to a different transaction. The node
test proves both differently directed spends pass that verifier. Only the default
transaction-bound template is eligible for the experimental payment helper.

## Test scope

Positive/negative tests cover every digest bit and every signature block,
all-zero/all-one/alternating digests, malformed lengths, wrong keys/messages,
concurrent reuse, DER edge values, s=0 rejection, reordered signature blocks,
extra/missing stack items, forged preimages, amounts, sequences, outpoints,
transaction version, locktime, outputs, multiple inputs and fresh-key change.
Both the development interpreter and the pinned independent chain-gang engine
run the complete-input matrix. BSV Node checks the same matrix through verifyscript
with explicit synthetic prevouts; it also demonstrates the detached-proof replay.
No real coins, network submission, mining, or mainnet policy acceptance is tested.
