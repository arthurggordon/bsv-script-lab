# Chronicle and P2PKH-R1-Deferred · 升级规则适用性

| Rule | Effect / 影响 |
|---|---|
| ForkID and OTDA | Activation fixes the digest type to ForkID SINGLE `0x43`. The final R1 spend follows the destination template's modes. 启用固定使用 BIP143，不启用 OTDA。 |
| `OP_CODESEPARATOR` | Activation checks the exact `01 ac` serialized scriptCode for the final executed separator. |
| Relaxed unlocking rules | The reference emits one data push. The short lock enforces the stack depth, exact preimage shape, and final native signature result. |
| Missing paired output | ForkID SINGLE yields zero `hashOutputs`. The lock rejects zero, including in malformed funding commitments. 缺少同索引输出时拒绝启用。 |

The [conformance entry point](../reference/README.md) uses actual serialized inputs and explicit prevouts and flags. The chain-gang result and BSV Node result are separate. Miner admission, policies and fees require separate measurements.
