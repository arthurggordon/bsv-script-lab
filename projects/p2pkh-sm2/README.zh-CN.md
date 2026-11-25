# P2PKH-SM2 v1.0.0

[English](README.md) · [BSV Script Lab](../../README.zh-CN.md)

付款方可以用收款人未压缩 SM2 公钥的 HASH160 锁定一笔 BSV 输出。花费时，
持有人公开该公钥，并为当前输入提供一次 SM2 签名。Bitcoin Script 使用 SM3 计算 SM2
用户标识摘要 ZA 和消息摘要，然后验证 SM2 签名，并通过 PUSHTX 和原生
`OP_CHECKSIG` 将授权绑定到实际的花费交易。

## 发布基线

v1.0.0 是首个公开版本。脚本生成器和 Python 钱包使用模板编号 `1` 标识本版的
基准锁定脚本。

| 项目 | 取值 |
| --- | --- |
| 收款标识 | 65 字节公钥 `04 \|\| X_BE32 \|\| Y_BE32` 的 HASH160 |
| SM2 用户标识 | 固定的 ASCII 字符串 `1234567812345678` |
| 锁定脚本 | 144,925 字节 |
| 解锁脚本 | ForkID 为 291 字节，无配对输出的 OTDA SINGLE 为 294 字节，其他 OTDA 模式的长度随交易变化 |
| 解锁栈 | 签名预映像、未压缩公钥，以及 64 字节的 `r \|\| s` 签名 |
| 交易签名模式 | ForkID 和 Chronicle OTDA 均支持 ALL、NONE、SINGLE，每种模式均可选用 ANYONECANPAY |

[发布页](https://github.com/linzhm/bsv-script-lab/releases/tag/p2pkh-sm2-v1.0.0)
对应的源码包含[模板布局](template/layout.json)、[SM2 标准向量](template/sm2-standard.json)、
[完整付款向量](template/spend-all.json)和 [16 个签名预映像](template/sighash-modes.json)。

## 生成锁定脚本

在仓库根目录运行下面的命令。示例中的哈希仅供演示，创建实际输出时请换成收款人的
公钥 HASH160。

```sh
cd projects/p2pkh-sm2/reference
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format raw > scriptPubKey.bin
```

第一条命令输出模板编号、脚本字节数和该收款脚本的 SHA-256。第二条命令将锁定脚本的
原始字节写入文件。也可以通过 `--public-key` 提供未压缩的收款公钥，生成器会先验证
公钥，再计算其哈希。

## 签署并验证付款

单输入付款可用 `sign_payment`，它使用 ForkID ALL（`0x41`）。交易已构造好时，
可用 `sign_input` 为不同输入分别选择签名模式。签署 OTDA 输入时，请提供实际花费时
的 Chronicle 激活状态。钱包调用外部签名器，验证返回的签名后再构造解锁脚本。
[协议规范](docs/spec.zh-CN.md) · [Python 参考实现与节点测试](reference/README.zh-CN.md)

钱包适配器支持 GB/T 35275-2026 `SignedData` 中由单个签名者直接对消息生成的
SM2 签名。封装的外层 `SignedData.version = 1`，内层 `SignerInfo.version = 2`。
Python 和 Rust 命令行签名器均使用专用测试密钥。[SignedData 接入指南](reference/README.zh-CN.md#signeddata-付款接入)
· [Python 测试签名器](reference/interop/python-signer/README.zh-CN.md)
· [Rust 测试签名器](reference/interop/rust-signer/README.zh-CN.md)
