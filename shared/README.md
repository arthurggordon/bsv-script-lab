# Shared development infrastructure

- `script.py`: dependency-free Script byte encoder and literal-block assembler. Migration tests reconstruct the existing R1 program byte for byte.
- `transaction.py`: legacy BSV transaction serialization and fixed ForkID ALL preimages. Each project chooses its scriptCode and signing algorithm.
- `evaluate.py`: local development evaluator for the generated opcode subset. It does not implement consensus flags, resource limits or network activation. The native CHECKSIG callback is required, and local tests use the independent `ecdsa` package.
- `verify_node.sh`: BSV Node 1.2.3 download/checksum verification and temporary regtest RPC validation. Run from a project's reference directory with its unittest module name. Projects retain their own chain-gang tests.
- `test_layout.py`: project-resource links and unchanged R1 template vectors.

Cryptographic parameters, identity policy, witness format and authorization coverage belong to each project. This directory is not a new consensus engine.
