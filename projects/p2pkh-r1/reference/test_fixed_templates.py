"""Conformance for the prebuilt full-mode template and OTDA reconstruction."""
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tx_engine import Script, Tx, TxIn, TxOut

from fixed_templates import TEMPLATE_DIRECTORY, compiled_template
from generate_templates import build_artifacts
from p2pkh_r1 import locking_script_from_owner_hash, recognize
from shared.evaluate import evaluate
from shared.transaction import Transaction, preimage_otda
from test_payment import check, fixture_signature, parent, signer
from wallet import sign_spend


def script(raw):
    value = Script()
    value.append_data(raw)
    return value


P2PKH = script(bytes.fromhex("76a914" + "00" * 20 + "88ac"))


class FixedTemplateTests(unittest.TestCase):
    def test_artifacts_and_owner_vectors(self):
        for file, content in build_artifacts().items():
            self.assertEqual((TEMPLATE_DIRECTORY / file).read_text(encoding="ascii"), content, file)
        layout = json.loads((TEMPLATE_DIRECTORY / "layout.json").read_text(encoding="ascii"))
        template = compiled_template()
        for vector in layout["owner_vectors"]:
            with self.subTest(owner=vector["owner_hash160"]):
                owner = bytes.fromhex(vector["owner_hash160"])
                raw = locking_script_from_owner_hash(owner, compiled_curve=True)
                self.assertEqual(sha256(raw).hexdigest(), vector["script_sha256"])
                self.assertEqual(recognize(raw), owner)
                for i in (0, template.owner_start - 1, template.owner_end, len(raw) - 1):
                    changed = raw[:i] + bytes([raw[i] ^ 1]) + raw[i + 1:]
                    self.assertIsNone(recognize(changed))
                self.assertIsNone(recognize(raw[:-1]))
                self.assertIsNone(recognize(raw + bytes(1)))

    def test_complete_transactions_and_marginals(self):
        keys, locks, funding = self.funding()
        for flag, profiles in (
            (0x41, ((2, 2, 326, 95790), (3, 2, 326, 96159), (2, 3, 326, 143311))),
            (0x61, ((2, 2, 6176, 107490), (3, 2, 6217, 113832), (2, 3, 6216, 155091))),
        ):
            for m, n, unlock_bytes, tx_bytes in profiles:
                with self.subTest(flag=hex(flag), inputs=m, outputs=n):
                    prev = funding[:m]
                    outputs = [TxOut(500, lock) for lock in locks[3:3+n]]
                    unsigned = Tx(2, [TxIn(p.id(), 0, Script()) for p in prev], outputs, 0)
                    signed = self.sign(unsigned, prev, keys[:m], flag, compress=True)
                    self.check_chronicle(signed, prev)
                    self.assertEqual([len(i.script_sig.raw_serialize()) for i in signed.tx_ins], [unlock_bytes] * m)
                    self.assertEqual(len(signed.serialize()), tx_bytes)
                    if flag == 0x41:
                        for i in range(m):
                            check(signed, prev, i, chronicle=False, funding_height=1)
                    if flag == 0x61 and (m, n) == (2, 2):
                        ordinary = self.sign(unsigned, prev, keys[:m], flag, compress=False)
                        self.check_chronicle(ordinary, prev)
                        self.assertEqual(len(ordinary.serialize()), 285762)

    def test_otda_reconstruction_preserves_the_preimage_and_output_binding(self):
        keys, locks, funding = self.funding()
        prev = funding[:2]
        outputs = [TxOut(700, P2PKH), TxOut(850, locks[3])]
        unsigned = Tx(2, [TxIn(p.id(), 0, Script()) for p in prev], outputs, 7)
        for flag in (0x61, 0xe1):
            compact = self.sign(unsigned, prev, keys[:2], flag, compress=True)
            literal = self.sign(unsigned, prev, keys[:2], flag, compress=False)
            self.check_chronicle(compact, prev)
            self.assertLess(len(compact.serialize()), len(literal.serialize()))
            for i, (large, small) in enumerate(zip(literal.tx_ins, compact.tx_ins, strict=True)):
                raw_stack, raw_alt = evaluate(large.script_sig.raw_serialize())
                packed_stack, packed_alt = evaluate(small.script_sig.raw_serialize())
                independent = preimage_otda(Transaction.parse(unsigned.serialize()), i, b"\x68\xac", flag)
                self.assertEqual(len(raw_stack), 5)
                self.assertEqual(raw_stack[0], independent)
                self.assertEqual((packed_stack, packed_alt), (raw_stack, raw_alt))
            changed_outputs = (
                [TxOut(699, P2PKH), outputs[1]],
                [outputs[1], outputs[0]],
                [outputs[0], TxOut(850, locks[4])],
            )
            for changed in changed_outputs:
                signed = Tx(2, compact.tx_ins, changed, compact.locktime)
                heights = [(p.id(), 0, 3) for p in prev]
                with self.assertRaises(ValueError):
                    signed.validate_with_chronicle_context(prev, 4, 2, heights, True)
                for i in range(len(prev)):
                    check(signed, prev, i, valid=False)

    def test_original_unlock_fallback(self):
        keys, locks, funding = self.funding()
        for flag, version, outputs in (
            (0x61, 1, [locks[3], locks[4]]),
            (0x61, 2, [P2PKH, P2PKH]),
            (0x62, 2, [locks[3], locks[4]]),
            (0x63, 2, [locks[3], locks[4]]),
            (0xe3, 2, [locks[3]]),
        ):
            with self.subTest(flag=hex(flag), version=version, outputs=len(outputs)):
                prev = funding[:2]
                unsigned = Tx(version, [TxIn(p.id(), 0, Script()) for p in prev],
                              [TxOut(900, x) for x in outputs], 0)
                literal = self.sign(unsigned, prev, keys[:2], flag, compress=False)
                optional = self.sign(unsigned, prev, keys[:2], flag, compress=True)
                self.assertEqual(optional.serialize(), literal.serialize())
                self.check_chronicle(optional, prev, push_only=version == 1)

    @staticmethod
    def funding():
        keys = [signer(i) for i in range(1, 7)]
        locks = [script(locking_script_from_owner_hash(owner, compiled_curve=True)) for _, _, owner in keys]
        return keys, locks, [parent(lock, 1000, f"{i+31:02x}") for i, lock in enumerate(locks[:3])]

    @staticmethod
    def sign(unsigned, funding, keys, flag, *, compress):
        inputs = []
        with TemporaryDirectory() as temp:
            history = Path(temp) / "history.db"
            for i, (previous, (key, public, _)) in enumerate(zip(funding, keys, strict=True)):
                unlock = sign_spend(unsigned, i, previous, flag, public,
                                    lambda digest: fixture_signature(key, digest), history, compress_otda=compress)
                inputs.append(TxIn(previous.id(), 0, unlock))
        return Tx(unsigned.version, inputs, unsigned.tx_outs, unsigned.locktime)

    @staticmethod
    def check_chronicle(tx, funding, *, push_only=False):
        heights = [(p.id(), 0, 3) for p in funding]
        tx.validate_with_chronicle_context(funding, 4, 2, heights, True)
        for i in range(len(funding)):
            check(tx, funding, i, extra_flags=(1 << 5) if push_only else 0)
