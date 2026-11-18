# Reference implementation

Python 3.12+; production primitive code uses only the standard library. Script
serialization and transaction helpers are under the repository's `shared/` folder.
Independent tests use the pinned chain-gang commit and BSV Node 1.2.3.

- `lamport.py`: random key generation, strict digest API, process-local one-time guard.
- `script.py`: deterministic unrolled verifier and fixed-r PUSHTX binding.
- `payment.py`: one-input transaction construction, fee arithmetic, fresh-change guard.
- `fixtures.py`: public deterministic secrets for tests only, adversarial case matrix.
- `engines.py`: development ECDSA callback and complete-transaction chain-gang adapter.
- `test_lamport.py`: unit, adversarial and differential tests; no node required.
- `test_node.py`: required node conformance (not silently skipped when absent).
- `measure.py`: reproducible vector and local benchmark.
- `verify_apple.sh`: Apple Container on macOS, pinned official node image, automatic cleanup.
- `verify.sh`: repository's Linux/CI node launcher; no container runtime required.

Run commands are in the [project README](../README.md). To export exact script
bytes for your **public test key**, from repository root:

```sh
.venv/bin/python - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, 'projects/03-lamport-ots/reference')
from fixtures import fixture
Path('/tmp/lamport-test-lock.bin').write_bytes(fixture()[2])
PY
```

The deterministic vector stores the full public key, signature, preimage, lock
fingerprint and transaction IDs; the secret derivation is published explicitly.
Regenerate with `measure.py --write-vector`; tests require exact JSON equality.
Do not fund this fixture. Real callers use `generate_keypair()` and a fresh
`OneTimeSigner`, authenticate their funding transaction, and approve outputs/fees
before calling `sign_payment`. The caller must add persistent key-use protection.

Apple Container uses host RPC port 18449 by default; set `LAMPORT_RPC_PORT` if
occupied. Its node has no peers and is removed after testing. Linux CI uses port
18443 and verifies the release archive against the release checksum manifest;
this is transport/checksum validation, not a pinned release-signing-key check.
