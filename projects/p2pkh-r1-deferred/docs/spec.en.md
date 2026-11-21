# P2PKH-R1-Deferred payment script

Developer RFC · [简体中文](spec.zh-CN.md)

## Funding and activation

For a value `v` and the recipient's 65-byte X9.63 P-256 public key `Q`, construct the canonical R1 script `S(Q)`. The short lock carries the public key, `SHA256(S(Q))`, the value, and `HASH256(TxOut(v, S(Q)))`. The serialized output consists of the eight-byte little-endian value, CompactSize script length, and script bytes. `HASH256` is double SHA-256.

A wallet can use the exposed public key to find candidate outputs. To accept a payment, it reconstructs the complete short lock using the actual output value and canonical target template, compares every byte, and matches the expected key and payment amount. The node enforces the output commitment. The wallet checks that the public key and script fingerprint correctly describe that commitment. Reused public keys make funding outputs linkable.

## Binary layout

Offsets are zero-based half-open ranges from the first locking opcode.

| Field | Range | Encoding |
|---|---|---|
| Owner key | `[1, 66)` | `04 || X_BE32 || Y_BE32`, a valid P-256 point |
| Target script fingerprint | `[67, 99)` | `SHA256(S(Q))` |
| Input value | `[154, 162)` | Eight-byte little-endian value |
| Target output commitment | `[179, 211)` | Nonzero `HASH256` of the complete `TxOut` |

The locking script is **1,480 bytes** and its complete `TxOut` is **1,491 bytes**. Zeroing the four mutable fields produces the fixed-byte SHA-256 fingerprint `f73e2c43cabf95938529d89802b8cbea957932c51b13a3265261a5087c1c316d`. Recognition also reconstructs and compares the entire script. [Canonical bytes](../template/template.hex) · [Layout and vectors](../template/layout.json)

## Spending the short lock

Activation input `i` creates the committed equal-value output at index `i`. Both paths use a PUSHTX signature constructed inside the lock and native signature verification to bind a BIP143 ForkID SINGLE preimage. The lock checks the input value and `hashOutputs` and rejects the zero hash for a missing paired output.

| Selected mode | Unlocking script | Verification |
|---|---|---|
| ForkID SINGLE `0x43`, `0xc3` | Push the 158-byte preimage for **160 bytes** total | Serialized scriptCode `01 ac` |
| Ten other modes | Push `typeByte || HASH256(selectedPreimage)`, then the 161-byte ForkID SINGLE preimage for **197 bytes** total | Check the output under serialized scriptCode `04 ad 68 ab ac`, then check the selected digest with `01 ac`. The `ANYONECANPAY` bits must agree |

Genesis supports the six ForkID modes. Chronicle enables six additional OTDA modes on the same locking template. An output at the input index is mandatory in every mode, including OTDA SINGLE `0x63` and `0xe3`. [Activation vectors](../template/sighash-modes.json) · [Lock assembly](../reference/asm/lock.asm)

Arrange each activation input at the index of its corresponding output, append fee inputs and change, and construct preimages after finalizing the transaction. Any party can fund and activate an output. The wallet tracks the confirmed activation outpoint. The recipient then uses the existing external R1 signer for the ordinary R1 spend. [P2PKH-R1 specification](../../p2pkh-r1/docs/spec.en.md)

Relative to direct funding, each activated payment adds a funding `TxOut` of 1,491 bytes and an activation input of 201 or 238 bytes. Transaction-wide framing, fee inputs and change are additional. Relay and miner policy require separate measurements.
