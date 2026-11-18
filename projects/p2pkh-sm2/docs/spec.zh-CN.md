# P2PKH-SM2 v1 规范

实验版本 · BRC 编号未分配 · [English](spec.en.md)

## 授权与支付模型

付款方通过收款方的 SM2 公钥哈希创建 UTXO。持有人在花费该 UTXO 时公开公钥，并对本次交易的当前输入授权。签名者只需要 SM2 私钥；用于交易绑定的 secp256k1 公钥和签名构造参数均为公开数据。

本版本使用 curveSM2 及标准 SM2 签名方程。原生 `OP_CHECKSIG` 的算法保持 secp256k1 ECDSA。SM2 验签和 SM3 哈希由已有 Bitcoin Script 指令实现，不增加操作码或修改节点。

## 公钥、标识与摘要

公钥编码固定为 65 字节：`04 || X_BE32 || Y_BE32`。必须检查坐标在 `[0,p)`，且点满足 curveSM2 曲线方程；无穷远点不接受。曲线余因子为 1。收款标识为该 65 字节编码的 HASH160。

本模板的 SM2 用户标识固定为 ASCII `1234567812345678`，共 16 字节，ENTLA 为其比特长度的两字节大端编码 `0080`。身份标识是签名算法的输入，并不证明真实身份或证书有效性。

```text
ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Qx || Qy)
H  = SHA256(SHA256(P))
e  = SM3(ZA || H)
```

曲线域元素均为 32 字节大端。脚本从实际提供的公钥计算 ZA；不接受调用方传入的 ZA、e 或 SM3 计算结果作为证明。ZA 输入前 128 字节是固定常量，可在生成脚本时预计算 SM3 中间状态。剩余两个压缩块以及 `SM3(ZA || H)` 的两个压缩块仍在脚本内执行。

标准 SM2 **消息签名接口**应传入消息 `H` 和用户标识 IDA。仅当设备明确提供 SM2 **预哈希签名接口**时，才传入 `e`；不得让设备对 e 再次计算 ZA 和 SM3。使用 SM3 是完整 SM2 签名方案的一部分；比特币交易摘要和收款公钥哈希仍保留 SHA256d 和 HASH160。

## 当前输入交易绑定

v1 固定使用 `0x41`（ForkID ALL），支持多输入、多输出交易中的单个输入授权。简化支付 API 生成一个输入、一个或多个输出的交易。NONE、SINGLE、ANYONECANPAY 和 OTDA 均不在本版模板范围内。

脚本末尾为 `OP_CODESEPARATOR OP_CHECKSIG`，因此当前输入的 scriptCode 是单字节 `ac`，序列化为 `01ac`。预映像 P 必须恰好为 158 字节：

```text
versionLE32 || hashPrevouts || hashSequence || outpoint || 01ac ||
amountLE64 || sequenceLE32 || hashOutputs || locktimeLE32 || 41000000
```

节点通过原生签名校验，将 H 绑定到实际交易的输入、输出、当前输入金额、序列号和锁定时间。该检查使用公开的 PUSHTX 构造，不能单独代表所有者授权；SM2 检查同时证明该 H 获得收款私钥持有人的签名。

脚本不接收序列化的父交易。钱包可在链下使用完整父交易核对 txid、索引、金额与锁定脚本；节点从 UTXO 上下文获得实际被花费输出。收款人验证交易和需要的 SPV 证据后，可将交易发给矿工。此参考钱包不实现区块头跟踪或默克尔证明验证。

## 验签条件

将签名解释为两个 32 字节大端整数 r、s，依次验证：

1. `1 <= r,s < n`。
2. `t = (r+s) mod n`，且 `t != 0`。
3. 计算 `R = sG + tQ`；拒绝无穷远点。
4. 验证 `r = (e + x(R)) mod n`。

脚本使用四位窗口和投影坐标运算。无需解锁方提供逆元。末步检查 `X = ((r-e) mod n) * Z mod p`，或者在第二候选小于 p 时检查 `X = (((r-e) mod n)+n) * Z mod p`。因为 `p < 2n`，两个候选完整覆盖坐标模 n 的情况。

SM2 不采用 ECDSA 的 low-S 归一化。不能将 s 随意替换为 n−s。

## 模板与见证

| 字段 | 字节数 / 位置 |
|---|---|
| 锁定脚本 | 199,530 字节 |
| 收款公钥哈希 | 零起点 `[50,70)`，20 字节 |
| P | 158 字节；序列化 push 共 160 字节 |
| Q | 65 字节；序列化 push 共 66 字节 |
| `r || s` | 64 字节；序列化 push 共 65 字节 |
| scriptSig | 291 字节，严格三个栈项 |

脚本识别必须检查全部固定程序字节，不能仅凭长度或前缀判断。所有者槽位以外的指纹、零所有者基础脚本哈希见 [layout.json](../template/layout.json)。[生成器](../reference/generate_lock.py) 直接输出 raw 或 hex；无需在仓库重复存放大体积展开字节。

## API 与拒绝条件

[Python API](../reference/p2pkh_sm2.py) 提供：

- `locking_script_from_owner_hash(owner)`：付款方只持有收款哈希即可生成脚本。
- `locking_script_from_public_key(key)`：校验完整 SM2 公钥并生成脚本。
- `recognize(raw)`：检查完整固定程序，返回所有者哈希或 None。
- `current_input_unlock(tx, index, previous_amount, key, signature)`：验证当前输入 SM2 授权并编码见证。
- `sign_payment(funding_raw, vout, outputs, fee, key, signer)`：核对父输出、密钥、金额及费用，调用 `signer(H, IDA)`，验证返回签名后组装交易。

调用者须确认父交易来源及确认状态，向签名设备展示或通过可信界面确认收款、找零和费用。Python 的公开曲线运算用于验证和测试，测试签名器要求显式传入公开测试 nonce；不得用于生产私钥签名。

## 验证与实施边界

测试覆盖标准向量、OpenSSL SM2 消息签名、SM3 分块边界与固定前缀中间状态、曲线/标量错误、错误用户标识、t=0、无穷远点、极少出现的 x≥n 第二候选、伪造预映像及交易字段篡改。三次连续转付验证见证长度保持 291 字节。

本地开发求值器只验证生成器所使用的操作码子集；它不代表共识实现。独立的 [节点测试](../reference/test_node.py) 在 BSV Node 1.2.3 与固定版本 chain-gang 中验证完整输入。测试使用显式 UTXO 和脚本 flags，不能代替主网激活条件、矿工策略、手续费报价或硬件集成测试。脚本较大，应基于实际矿工报价评估创建输出的成本。

## 来源与致谢

- [RFC 8998 §3.2.1](https://www.rfc-editor.org/rfc/rfc8998.html#section-3.2.1)：curveSM2 参数及 SM2 用户标识语义。
- [OpenSSL 标准测试](https://github.com/openssl/openssl/blob/openssl-3.5.0/test/sm2_internal_test.c)：GM/T 0003.5-2012 和 GB/T 32918.5-2016 附录 A 签名向量。
- [SM3 算法描述](https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3-02)：压缩函数、消息扩展和示例；此文档为 Internet-Draft。
- [nChain WP1605](https://nchain.com/wp-content/uploads/2022/03/WP1605_PUSHTX-and-its-Building-Blocks.pdf)、[BRC-21](https://github.com/bsv-blockchain/BRCs/blob/master/scripts/0021.md)：公开 PUSHTX 交易绑定构造。
- [P2PKH-R1](../../p2pkh-r1/README.md)：本仓库已有的 a=−3 投影坐标运算、窗口结构与公开原生签名构造；SM2 使用独立常量和签名方程。
