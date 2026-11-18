# Project 03 · Lamport OTS (SHA-256)

Experimental, directly unrolled 256-bit Lamport one-time signatures in BSV Script.
Includes secure random key generation, digest signing/verification, an in-memory
one-use signing guard, complete transaction construction, and independent engine tests.

**实验项目，不是已审计钱包。每组密钥只能签名一次，且只能用于一个 UTXO。**
`OneTimeSigner` only prevents reuse of the same object in one process. It does not
protect copied keys, process restarts, backups, rollback, or duplicate funding.

## Two explicitly different verifiers

- `locking_script(key, transaction=False)` checks a supplied 32-byte digest only.
  **Never fund this script**: an observer can replay the proof into another spend.
- `locking_script(key)` additionally binds the authorized digest to the current
  input using a fixed-r PUSHTX construction and native `OP_CHECKSIG`, fixed ForkID
  ALL (`0x41`). No externally supplied ECDSA signature can bypass the binding.

The hash-based signature is a post-quantum research building block. The complete
payment construction needs its own security analysis: [binding and one-time
boundaries](docs/security.md). We do not claim an audited end-to-end PQ payment
system or a standardized “256-bit quantum security” level.

## Measured bytes

| Item | Bytes |
|---|---:|
| Secret key / public key | 16,384 each |
| Signature | 8,192 |
| Digest-only locking script, including public key | 21,876 |
| Transaction locking script, including public key | 22,491 |
| Non-key portion of transaction lock, including push headers | 6,107 |
| Unlocking script, including preimage and push headers | 8,355 |
| Lock + unlock | 30,846 |

The previous 26–32 KiB estimate is consistent with this 30.12 KiB combined result;
6,107 bytes are the non-key portion, not the entire verifier. The spent lock is
stored in the funding transaction, not repeated in the 8,418-byte example spend.
Timings and opcode definitions: [measurement.json](template/measurement.json).

## Run

From repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r projects/03-lamport-ots/reference/requirements.txt
python -m unittest discover -s projects/03-lamport-ots/reference -p test_lamport.py -v
python projects/03-lamport-ots/reference/measure.py --benchmark
# macOS, Apple Container (no Docker daemon):
bash projects/03-lamport-ots/reference/verify_apple.sh
# Linux / CI, isolated downloaded BSV Node 1.2.3:
bash projects/03-lamport-ots/reference/verify.sh
```

[Validation receipt](docs/validation.md) · [Protocol and layout](docs/spec.md) · [Reference usage](reference/README.md) ·
[Public deterministic test vector](template/vector.json)
