# Shared development utilities

Dependency-free Script encoding, ForkID BIP143 and Chronicle OTDA preimage serialization,
a deliberately incomplete development interpreter, and a BSV Node 1.2.3 Linux
regtest launcher. Extracted from the local SM2 experiment for the third project;
the existing top-level R1 implementation and its canonical bytes are unchanged.

`evaluate.py` is **not a consensus engine**: it does not model activation,
resource limits, all Script opcodes, or native transaction checks. Use the pinned
chain-gang engine and `verify_node.sh` for complete-input conformance.

`transaction.preimage_all` defaults to scriptCode `ac`, suitable only for templates
whose final executed code separator leaves exactly `OP_CHECKSIG`. Funding data
must be authenticated by the caller. None of these helpers manages wallet state.
