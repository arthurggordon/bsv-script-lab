# Validation receipt · 2026-11-19 (Asia/Shanghai)

Source base: `6b90bb0` on GitHub main. The local workspace also contained an
uncommitted SM2 project and R1 directory migration; those are not part of this
third-project change. No existing R1 source/template/SDK files were modified.

## Executed checks

| Check | Result |
|---|---|
| Lamport unit/adversarial/differential suite | 10 test methods passed; includes 256 individual digest-bit and 256 signature-block mutations |
| BSV Node 1.2.3 + pinned chain-gang | 32 complete-input cases agreed (2 valid, 30 invalid) |
| BSV Node additional tests | Fresh-key payment chain and detached-proof replay demonstration passed |
| Existing R1 complete suite | 4 test methods passed against the same isolated BSV Node |
| Local SM2 regression, outside this Git branch | 11 test methods passed, including OpenSSL interoperability |
| Local migration/layout checks, outside this Git branch | 2 passed, including unchanged R1 canonical fingerprint |
| Dependency provenance | chain-gang commit `5cb8c6e410dbfad1c619cec3ca54d1bcaacd4eb7` verified from installed distribution metadata |
| Deterministic vector | Regenerated JSON matches checked-in vector |
| Shell syntax and project documentation links | Passed |

The node ran through **Apple Container 1.7.1** using official image manifest
`sha256:d96fe4786a00e5fc10bc9e0e76a6006376f9472d4eb74d07e4c1e0d019493d33`,
linux/amd64 under Apple Silicon translation. RPC was bound on host loopback, peers
were disabled, and the temporary container and data were removed after each run.
The tests use synthetic prevouts and do not submit transactions to a network.

## Measurements

The full lock is 22,491 bytes; the unlock is 8,355 bytes; combined 30,846 bytes
(30.12 KiB). The embedded public key is 16,384 bytes; the signature is 8,192 bytes.
The non-key lock portion is 6,107 bytes including data-push headers.

For the public fixture, the development interpreter observed at most 5 main-stack
items, 32 altstack items, 33 combined items, and 8,512 combined payload bytes.
These peaks are measured separately and do not include node allocator overhead;
they are not a consensus memory accounting claim.

Thirty warm samples on macOS arm64 / Python 3.12.16 gave median key generation
0.270 ms, signing 0.045 ms, reference verification 0.154 ms, and chain-gang complete
transaction verification 0.293 ms. Full min/median/max and environment metadata
are in [measurement.json](../template/measurement.json). Node execution timing,
miner throughput, mainnet fees and relay acceptance are not inferred from these
host measurements.

## Reproduction

Use the commands in the [project README](../README.md). For R1 regression together
with the Lamport node tests, from this branch's repository root:

```sh
PATH="$PWD/.venv/bin:$PATH" PYTHONPATH="$PWD/reference" LAMPORT_RPC_PORT=18443 \
  bash projects/03-lamport-ots/reference/verify_apple.sh test_payment
```

The local SM2 checks used a separate existing workspace; they are historical
regression evidence here, not a claim that this branch ships the SM2 project.
GitHub CI additionally repeats Lamport checks with a Linux BSV Node release build
and uploads runner-specific benchmark output.
