# P2PKH-R1-Deferred

[BSV Script Lab](../../README.md) · Deferred P-256 payment template / 延迟启用的 R1 付款模板

An 801-byte funding script publishes the recipient's uncompressed P-256 public key and target script hash. It commits to the complete P2PKH-R1 output created at activation. The activation input carries a 160-byte ForkID SINGLE unlocking script. The resulting output uses ordinary [P2PKH-R1](../p2pkh-r1/README.md) authorization.

短锁公开收款人的 R1 公钥和目标脚本哈希，便于钱包筛选并核对收款。启用时只能创建承诺的同索引输出。收款人随后使用原有 R1 钱包授权花费。

| Developer resource | 中文 | English |
|---|---|---|
| Script template, wire format and transaction rules | [协议规范](docs/spec.zh-CN.md) | [Specification](docs/spec.en.md) |
| TypeScript, Rust and Go wallet integration | [SDK 接入](docs/sdk.zh-CN.md) | [SDK guide](docs/sdk.en.md) |
| Consensus rules and validation scope | [Chronicle 规则](docs/chronicle.md) | [Chronicle rules](docs/chronicle.md) |

The [binary layout and generation vectors](template/layout.json) define recognition. The [activation vector](template/activation-single.json) supplies the funding transaction, exact preimage, unlocking bytes and activation txid for offline replay. The [reference implementation](reference/README.md) builds complete batches, and the SDKs generate and recognize the same locks and encode prepared activation preimages.

**Status** · Experimental. BSV Node 1.2.3 conformance and independent review remain open.
