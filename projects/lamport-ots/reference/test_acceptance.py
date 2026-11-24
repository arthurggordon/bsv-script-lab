"""Exhaustive bounded acceptance checks for the repository Lamport profiles."""
from dataclasses import replace
from hashlib import sha256
from itertools import product
import os
import unittest

from engines import chain_valid
from fixtures import cases, mode_fixture, test_secret
from lamport import public_key, sign_digest, verify_digest
from script import locking_script
from shared.evaluate import evaluate, ScriptError
from shared.transaction import Output
from test_node import node_check


VERSIONS = (1, 2)
PAIRING = (False, True)
# The twelve byte values and commitment groups are specified in docs/spec.md.
ALL = {0x41, 0x61, 0xc1, 0xe1}
NONE = {0x42, 0x62, 0xc2, 0xe2}
SINGLE = {0x43, 0x63, 0xc3, 0xe3}
ANYONECANPAY = {0xc1, 0xc2, 0xc3, 0xe1, 0xe2, 0xe3}
MODES = sorted(ALL | NONE | SINGLE)
EDITS = (
    'unchanged', 'other_output', 'other_sequence', 'other_outpoint', 'own_sequence',
    'locktime', 'version', 'pairing_changed', 'paired_output',
)
LEGACY_CASES = frozenset("""
    valid output_amount supplied_output_amount output_script supplied_output_script
    locktime supplied_locktime version supplied_version sequence supplied_sequence
    outpoint_index supplied_outpoint_index outpoint_hash supplied_outpoint_hash
    short_pre long_pre wrong_flag wrong_script_code wrong_amount short_sig long_sig
    wrong_sig swapped_blocks wrong_key wrong_digest extra_item missing_item
    multi_input output_order other_sequence other_outpoint
""".split())


def edited_payments(signed, parents):
    """Keep the original witness on the signing input for every edit."""
    other, owned = parents
    first, current = signed.inputs
    first_output = signed.outputs[0]
    new_other = replace(other, locktime=1)
    yield 'unchanged', signed, parents
    yield 'other_output', replace(
        signed, outputs=(replace(first_output, value=first_output.value - 1), *signed.outputs[1:]),
    ), parents
    yield 'other_sequence', replace(signed, inputs=(replace(first, sequence=1), current)), parents
    yield 'other_outpoint', replace(
        signed, inputs=(replace(first, txid=new_other.txid_wire()), current),
    ), (new_other, owned)
    yield 'own_sequence', replace(signed, inputs=(first, replace(current, sequence=1))), parents
    yield 'locktime', replace(signed, locktime=1), parents
    yield 'version', replace(signed, version=3 - signed.version), parents
    paired = len(signed.outputs) == 2
    outputs = (first_output,) if paired else (first_output, Output(1, b'\x51'))
    yield 'pairing_changed', replace(signed, outputs=outputs), parents
    if paired:
        second = signed.outputs[1]
        yield 'paired_output', replace(signed, outputs=(first_output, replace(second, value=second.value - 1))), parents


class LamportAcceptance(unittest.TestCase):
    def test_every_commitment_selection_and_its_counterexamples(self):
        secret = test_secret(b'acceptance/commitment-slots')
        blocks = [secret[i:i+32] for i in range(0, len(secret), 32)]
        commitments = b''.join(sha256(block).digest() for block in blocks)
        self.assertEqual(public_key(secret), commitments)
        lock = locking_script(commitments, transaction=False)
        expected = set(product((0, 1), range(256), ('digest_bit', 'signature_slot', 'matching_flip')))
        visited = set()
        for choice in (0, 1):
            digest = bytes((255 * choice,)) * 32
            signature = b''.join(blocks[choice::2])
            self.assertEqual(sign_digest(secret, digest), signature)
            self.assertTrue(verify_digest(commitments, digest, signature))
            self.assertEqual(evaluate(lock, [digest, signature]), ([b'\x01'], []))
            for index in range(256):
                byte_index, bit_index = divmod(index, 8)
                changed_digest = bytearray(digest)
                changed_digest[byte_index] ^= 1 << bit_index
                changed_digest = bytes(changed_digest)
                slot = 32 * index
                opposite = blocks[2 * index + 1 - choice]
                changed_signature = signature[:slot] + opposite + signature[slot+32:]
                for edit, message, candidate in (
                    ('digest_bit', changed_digest, signature),
                    ('signature_slot', digest, changed_signature),
                    ('matching_flip', changed_digest, changed_signature),
                ):
                    row = (choice, index, edit)
                    with self.subTest(row=row):
                        self.assertNotIn(row, visited)
                        visited.add(row)
                        matches = edit == 'matching_flip'
                        self.assertEqual(verify_digest(commitments, message, candidate), matches)
                        if matches:
                            self.assertEqual(sign_digest(secret, message), candidate)
                            self.assertEqual(evaluate(lock, [message, candidate]), ([b'\x01'], []))
                        else:
                            with self.assertRaises(ScriptError):
                                evaluate(lock, [message, candidate])
        self.assertEqual(visited, expected)
        self.assertEqual(len(visited), 1536)

    def test_universal_payment_decisions_cover_the_declared_domain(self):
        expected = {
            (version, paired, mode, edit)
            for version, paired, mode, edit in product(VERSIONS, PAIRING, MODES, EDITS)
            if paired or edit != 'paired_output'
        }
        allowed = {
            'unchanged': set(MODES),
            'other_output': NONE | SINGLE,
            'other_sequence': NONE | SINGLE | ANYONECANPAY,
            'other_outpoint': ANYONECANPAY,
            'own_sequence': set(),
            'locktime': set(),
            'version': set(),
            'pairing_changed': NONE,
            'paired_output': NONE,
        }
        accepted = {row for row in expected if row[2] in allowed[row[3]]}
        self.assertEqual((len(expected), len(accepted)), (408, 168))
        visited = set()
        for version, paired, mode in product(VERSIONS, PAIRING, MODES):
            _, parents, signed = mode_fixture(mode, paired=paired, version=version)
            for edit, candidate, prevouts in edited_payments(signed, parents):
                row = (version, paired, mode, edit)
                with self.subTest(row=row):
                    self.assertIn(row, expected)
                    self.assertNotIn(row, visited)
                    visited.add(row)
                    self.assertEqual(chain_valid(candidate, prevouts), row in accepted, 'chain-gang')
                    if os.environ.get('REGTEST_COOKIE'):
                        self.assertEqual(node_check(candidate, prevouts[1], 1), row in accepted, 'BSV Node')
        self.assertEqual(visited, expected)

    def test_legacy_cases_match_the_declared_inventory(self):
        visited = set()
        for name, tx, parents, index, fixture_verdict in cases():
            with self.subTest(name=name):
                self.assertNotIn(name, visited)
                visited.add(name)
                expected = name in {'valid', 'multi_input'}
                self.assertEqual(fixture_verdict, expected)
                self.assertEqual(chain_valid(tx, parents), expected, 'chain-gang')
                if os.environ.get('REGTEST_COOKIE'):
                    self.assertEqual(node_check(tx, parents[index], index), expected, 'BSV Node')
        self.assertEqual(visited, LEGACY_CASES)
        self.assertEqual(len(visited), 32)


if __name__ == '__main__':
    unittest.main()
