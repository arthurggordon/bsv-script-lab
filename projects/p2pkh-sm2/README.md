# P2PKH-SM2 v1.0.0

[简体中文](README.zh-CN.md) · [BSV Script Lab](../../README.md)

P2PKH-SM2 lets a payer lock a BSV output to the HASH160 of the recipient’s
uncompressed SM2 public key. To spend the output, the recipient reveals the
public key and supplies one SM2 signature for the current input. Bitcoin Script
uses SM3 to compute the SM2 identity digest ZA and the message digest. It
verifies the SM2 signature and binds the authorization to the spending
transaction through PUSHTX and native `OP_CHECKSIG`.

## Release baseline

v1.0.0 is the first public release. The generator and the Python wallet
identify its canonical locking script as template version `1`.

| Property | Value |
| --- | --- |
| Recipient identifier | HASH160 of the 65-byte public key `04 \|\| X_BE32 \|\| Y_BE32` |
| SM2 user ID | The fixed ASCII value `1234567812345678` |
| Locking script | 144,925 bytes |
| Unlocking script | 291 bytes with ForkID, 294 bytes with unpaired OTDA SINGLE, and transaction-dependent for other OTDA modes |
| Unlocking stack | Signing preimage, uncompressed public key, and 64-byte `r \|\| s` signature |
| Signature modes | ForkID and Chronicle OTDA, each with ALL, NONE, or SINGLE and optional ANYONECANPAY |

The [release](https://github.com/linzhm/bsv-script-lab/releases/tag/p2pkh-sm2-v1.0.0)
includes the [layout manifest](template/layout.json),
[standard SM2 vector](template/sm2-standard.json),
[complete payment vector](template/spend-all.json), and
[16 signing preimages](template/sighash-modes.json).

## Generate a locking script

Run these commands from the repository root. The owner hash below is an
example. Substitute the recipient’s HASH160 for an actual output.

```sh
cd projects/p2pkh-sm2/reference
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format raw > scriptPubKey.bin
```

The first command reports the template version, byte length, and SHA-256 for
the supplied owner. The second writes the exact locking script bytes. Use
`--public-key` to supply the recipient’s uncompressed public key instead of
its hash. The generator validates the public key before hashing it.

## Authorize and verify a payment

Use `sign_payment` for a one-input ForkID ALL payment (`0x41`). Use
`sign_input` to choose a signature mode for each input of a prepared
transaction. For OTDA, pass the Chronicle activation state for the actual
spend. The wallet calls an external signer and verifies the returned signature
before building the unlocking script. [Protocol specification](docs/spec.en.md)
· [Python reference and node tests](reference/README.md)

The wallet adapter accepts a direct SM2 signature from a single signer in a
GB/T 35275-2026 `SignedData` envelope. The envelope uses
`SignedData.version = 1` and `SignerInfo.version = 2`. The Python and Rust
command-line signers use dedicated test keys. [SignedData integration](reference/README.md#signeddata-payment-interop)
· [Python test signer](reference/interop/python-signer/README.md)
· [Rust test signer](reference/interop/rust-signer/README.md)
