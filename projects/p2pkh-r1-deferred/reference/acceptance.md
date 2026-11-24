# P2PKH-R1-Deferred activation acceptance

The fixture activates input 1 of a two-input transaction into its corresponding
R1 output, with a sponsor input at index 0. It evaluates both canonical hash-only
funding locks and the earlier full-key format. The expected decisions follow the
[activation specification](../docs/spec.en.md#spending-the-short-lock).

| Axis | Values |
| --- | --- |
| Funding layout | 1,435-byte hash-only lock, 1,480-byte full-key lock |
| Transaction version | 1, 2 |
| Sighash | ALL, NONE or SINGLE × ForkID or OTDA × with or without ANYONECANPAY |
| Rule context | Genesis UTXO and Genesis spend, Genesis UTXO and Chronicle spend, Chronicle UTXO and Chronicle spend |
| Activation case | Unchanged, fresh witness for wrong target amount, fresh witness for wrong recipient script, missing target, changed sponsor output, changed activation sequence, fresh witness with wrong binding amount, extra stack item |

An unchanged witness passes in the applicable context. The Genesis context
rejects all OTDA modes. The mandatory ForkID SINGLE binding must always commit
to the equal-value target at the activation input's index. The fixture supplies
fresh preimages for wrong target amounts and scripts below the wallet's preflight
to exercise the lock's own check. Changing the sponsor output with a stale
authorization is allowed by NONE and SINGLE. ALL catches the change through
its selected digest. The remaining mutations must all fail.

The test rejects duplicated axis values, asserts that each visited tuple
belongs to the product and occurs once, then checks the exact product size
`2 × 2 × 12 × 3 × 8 = 1,152`. A subset of a finite set with the same cardinality
equals the entire set. The [ordinary R1 acceptance matrix](../../p2pkh-r1/reference/acceptance.md)
covers the subsequent recipient signature on the activated output.
Deliberately omitting one tuple caused the cardinality check to fail at 1,151.

BSV Node 1.2.3 matched all 1,152 results, with 40 accepts in Genesis and
80 accepts in each Chronicle context. The pinned chain-gang build matched the
384-row Chronicle UTXO subset, with 80 accepts and 304 rejects.

From the repository root, run the [standard verification entry point](verify.sh).

```sh
python -m pip install -r projects/p2pkh-r1-deferred/reference/requirements.txt
bash projects/p2pkh-r1-deferred/reference/verify.sh
```

The proof covers the declared two-input, two-funding-format product.
Arbitrary activation transactions, blanket validation of untrusted funding
locks, and network admission policy require separate evidence.
