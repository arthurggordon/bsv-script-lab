# P2PKH-R1-Deferred payment script

Developer RFC · [简体中文](spec.zh-CN.md)

## Funding and activation

For a value `v` and the recipient's 65-byte X9.63 P-256 public key `Q`, construct the canonical R1 script `S(Q)`. The short lock carries the public key, `SHA256(S(Q))`, the value, and `HASH256(TxOut(v, S(Q)))`. The serialized output consists of the eight-byte little-endian value, CompactSize script length, and script bytes. `HASH256` is double SHA-256.

A wallet can use the exposed public key to find candidate outputs. To accept a payment, it reconstructs the complete short lock using the actual output value and canonical target template, compares every byte, and matches the expected key and payment amount. The node enforces the output commitment. The wallet checks that the public key and script fingerprint correctly describe that commitment. Reused public keys make funding outputs linkable.

## Binary layout

Offsets are zero-based half-open ranges from the first locking opcode.

| Field | Range | Encoding |
|---|---|---|
| Version tag | `[1, 9)` | ASCII `R1DEFER` followed by `0x01` |
| Owner key | `[10, 75)` | `04 || X_BE32 || Y_BE32`, a valid P-256 point |
| Target script fingerprint | `[76, 108)` | `SHA256(S(Q))` |
| Input value | `[139, 147)` | Eight-byte little-endian value |
| Target output commitment | `[166, 198)` | Nonzero `HASH256` of the complete `TxOut` |

The locking script is **801 bytes** and its complete `TxOut` is **812 bytes**. Zeroing the four mutable fields produces the fixed-byte SHA-256 fingerprint `844eaecb0dc475389c5c3012042d98792243dc6eb84eea78bd7dc3bc4dd28cf6`. Recognition also reconstructs and compares the entire script. [Canonical bytes](../template/template.hex) · [Layout and vectors](../template/layout.json)

## Spending the short lock

Activation input `i` creates the committed equal-value output at index `i`. The lock uses a PUSHTX signature constructed inside the script and native `OP_CHECKSIG` to bind the preimage to the actual transaction. The required mode is BIP143 ForkID SINGLE `0x43`. The final executed `OP_CODESEPARATOR` leaves only `OP_CHECKSIG`, with serialized scriptCode `01 ac`. The lock checks the input value and `hashOutputs` and rejects the zero hash for a missing paired output. The unlocking script is one push of the **158-byte** preimage, occupying **160 bytes**. [Activation vector](../template/activation-single.json) · [Lock assembly](../reference/asm/lock.asm)

Arrange each activation input at the index of its corresponding output, append fee inputs and change, and construct preimages after finalizing the transaction. Any party can fund and activate an output. The wallet tracks the confirmed activation outpoint. The recipient then uses the existing external R1 signer for the ordinary R1 spend. [P2PKH-R1 specification](../../p2pkh-r1/docs/spec.en.md)

Relative to direct funding, each activated payment adds a funding `TxOut` of 812 bytes and an activation input of 201 bytes. Transaction-wide framing, fee inputs and change are additional. These wire sizes do not establish node relay or miner policy.
