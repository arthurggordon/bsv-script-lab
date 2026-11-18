# Lamport SHA-256 v1 wire and Script specification

## Primitive

For i=0..255 and b=0,1, independently generate a uniformly random 32-byte secret
x[i][b]. Publish y[i][b]=SHA256(x[i][b]). Serialize in order x[0][0], x[0][1],
x[1][0], x[1][1], ...; the public key uses the same order. Both are 16,384 bytes.
The 32-byte digest D is read in byte order, **LSB-first within each byte**:
b[i]=(D[i//8] >> (i%8)) & 1. Signature block i is x[i][b[i]], giving 8,192 bytes.
Verify exactly 256 SHA-256 preimages against the selected public commitments.
Reject every incorrect length; there is no padding or truncation.

This is an explicit repository encoding of Lamport OTS, not a NIST-standardized
signature format. The public deterministic fixture is a regression vector, not
an official standard test vector. `generate_keypair()` uses OS-backed randomness;
the fixture derivation is deliberately separate and must never hold funds.

## Script and stack

Full public commitments are inline in the locking script, with two 32-byte pushes
per bit. The witness has exactly two stack elements: P (158 bytes), S (8,192 bytes).
Signature blocks remain packed and are consumed with SPLIT; no 256-item witness
stack or 512-item public-key stack is required. Each byte is converted to an
unsigned integer by appending a zero byte before BIN2NUM. MOD 2 chooses the key
branch, DIV 2 advances to the next bit. All bytes and blocks must be consumed.
The final stack is exactly one true item and the altstack is empty.

The digest-only variant substitutes a 32-byte D for P and returns true after
Lamport verification. It deliberately does not authorize any transaction.

## Current-input payment digest

D = SHA256d(P), with P the BIP143/ForkID ALL serialization:

| Offset | Length | Field |
|---|---:|---|
| 0 | 4 | Transaction version, LE |
| 4 | 32 | SHA256d(all input outpoints) |
| 36 | 32 | SHA256d(all input sequences) |
| 68 | 36 | Current outpoint |
| 104 | 2 | CompactSize + scriptCode, exactly `01 ac` |
| 106 | 8 | Current prevout satoshis, LE |
| 114 | 4 | Current sequence, LE |
| 118 | 32 | SHA256d(all serialized outputs) |
| 150 | 4 | Locktime, LE |
| 154 | 4 | Sighash type, exactly `41 00 00 00` |

The script enforces total length, scriptCode, and type before hashing. The final
`OP_CODESEPARATOR OP_CHECKSIG` means the native checker hashes scriptCode `ac`.
The other fields are authenticated by the fixed-r native-check relation described
in [security.md](security.md), not by trusting the witness or a host callback.
All inputs' outpoints/sequences and all outputs are committed. ScriptSigs,
other inputs' amounts/scripts and funding-chain validity are not authenticated
by this signature. Wallets must authenticate their UTXOs separately.

No ANYONECANPAY, SINGLE, NONE, OTDA, optional recovery path, or mutable fee mode is
supported. Multi-input transactions use `current_input_unlock` once for each
fresh Lamport key. The higher-level `sign_payment` API intentionally constructs
one input and rejects change to the same canonical Lamport key.

## Compatibility and resources

The code uses Genesis-era SPLIT, CAT, arithmetic and large pushed elements, and
requires post-Genesis resource rules (an 8,192-byte element and thousands of
opcodes exceed historical 520-byte/201-op limits). The conformance runner tests
BSV Node 1.2.3 in isolated regtest with Genesis height 1, Chronicle height 2,
synthetic prevout height 3, explicit flags and a 100 MB stack-memory limit. It
never broadcasts or mines the transactions. This demonstrates Script acceptance
under those settings, not mainnet relay policy, fee acceptance, UTXO existence,
or network-wide consensus testing. Node tests also cross-check pinned chain-gang.

Static opcode counts in `measurement.json` exclude payload bytes; both branches
are counted in the encoded instruction totals, although only one public-key push
per bit executes. There are 256 SHA256, one HASH256 and one CHECKSIG instructions.
Node-native signature hashing performs additional work not counted by this static
Script census. Timings include adapters and are local wall-clock samples.

## Sources

- [Lamport, Constructing Digital Signatures from a One Way Function](https://www.microsoft.com/en-us/research/publication/constructing-digital-signatures-one-way-function/).
- [BSV protocol specifications](https://github.com/bitcoin-sv-specs/protocol), including Genesis and Chronicle.
- [BSV Node releases](https://github.com/bitcoin-sv/bitcoin-sv/releases).
- The existing R1 project credits PUSHTX research; its fixed-key DER construction
  and the local SM2 experiment informed this binding, without changing R1 bytes.
