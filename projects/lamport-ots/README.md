# Lamport OTS (SHA-256)

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
  input using fixed-r PUSHTX. It supports ForkID BIP143 and Chronicle OTDA
  ALL, NONE and SINGLE, each with optional ANYONECANPAY. The wallet default
  is ForkID ALL (`0x41`). Production signing uses an external callback.

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
| Universal locking script, including public key | 22,780 |
| Non-key portion of transaction lock, including push headers | 6,396 |
| Ordinary BIP143 unlocking script | 8,357 |
| Unpaired OTDA SINGLE unlocking script | 8,361 |
| Lock + ordinary BIP143 unlock | 31,137 |

The universal BIP143 ALL path totals 30.41 KiB. The original two-push
ForkID ALL lock and vector remain available. OTDA ordinary witness size
varies with the serialized transaction. Full measurements are in
[measurement.json](template/measurement.json).

## Run

From repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r projects/lamport-ots/reference/requirements.txt
python -m unittest discover -s projects/lamport-ots/reference -p test_lamport.py -v
python -m unittest discover -s projects/lamport-ots/reference -p test_acceptance.py -v
python projects/lamport-ots/reference/measure.py --benchmark
# macOS, Apple Container (no Docker daemon):
bash projects/lamport-ots/reference/verify_apple.sh
# Linux / CI, isolated downloaded BSV Node 1.2.3:
bash projects/lamport-ots/reference/verify.sh
```

[Acceptance domain and coverage proof](docs/acceptance.md) · [Validation receipt](docs/validation.md) · [Protocol and layout](docs/spec.md) · [Reference usage](reference/README.md) ·
[Original ALL vector](template/vector.json) ·
[Universal sighash vectors](template/universal-vectors.json)

## Committed-key candidate

`committed_locking_script(key)` opts in to the experimental 7,746-byte lock.
It stores SHA-256 of the existing ordered 16,384-byte Lamport public key.
For each digest bit, the witness supplies its usual 32-byte secret and the
32-byte public hash for the opposite bit. The script hashes the secret,
orders each pair by the preimage digest, reconstructs the public key, and
checks its commitment. The two proof halves use the same key and bit order
as the existing Lamport signer. The wallet still requests one 8,192-byte
signature from the external signer. It needs the full public key off chain
to construct the proof. Keep that key or the data required to derive it
available to the wallet. Use fresh keys across formats and persist key
consumption before disclosing a signature.

The candidate saves 15,034 bytes per lock and adds 8,192 bytes to an ordinary
ForkID witness. These complete, signed transactions use fresh, synthetic
Lamport keys for every input and output. Marginal costs are measured from the
2-input, 2-output payment.

| Mode and format | 2 inputs, 2 outputs | Extra input | Extra output |
| --- | ---: | ---: | ---: |
| ForkID ALL, full key | 62,392 B | 8,400 B | 22,791 B |
| ForkID ALL, commitment | 48,708 B | 16,592 B | 7,757 B |
| Chronicle OTDA ALL, full key | 153,436 B | 54,045 B | 68,381 B |
| Chronicle OTDA ALL, commitment | 79,616 B | 32,169 B | 23,271 B |

The ForkID format favors the committed lock when the number of Lamport
outputs divided by the number of Lamport inputs exceeds `8192/15034`. This
uses the same transaction framing and CompactSize widths. OTDA ALL repeats
the serialized outputs in each signing preimage, so the shorter output
reduces each input witness as well.

Over the full lifecycle, use the same native P2PKH funding input and the
same two native P2PKH exit outputs. Both Lamport outputs are funded and
later spent. A turnover spends both Lamport inputs into two fresh Lamport
outputs before exit.

| Path | Full-key lifecycle | Committed-key lifecycle |
| --- | ---: | ---: |
| ForkID ALL, fund and exit | 62,618 B | 48,933 B |
| ForkID ALL, one turnover | 125,009 B | 97,641 B |
| Chronicle OTDA ALL, fund and exit | 62,631 B | 48,947 B |
| Chronicle OTDA ALL, one turnover | 216,068 B | 128,563 B |

Exiting directly to ordinary outputs adds 8,192 witness bytes per committed
input. When funding and exit pay different fees per byte, compare the
15,034-byte funding reduction and the 8,192-byte exit increase separately.

```sh
python projects/lamport-ots/reference/measure.py --committed-costs
bash projects/lamport-ots/reference/verify.sh
```

The acceptance suite runs the 408-row payment decision matrix for both
formats. It also flips one bit in each of the 512 proof positions of one
committed spend, tests short and long proofs, and checks the Chronicle
activation boundary in BSV Node.
