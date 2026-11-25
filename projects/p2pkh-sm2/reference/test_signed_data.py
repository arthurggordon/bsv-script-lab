"""Verify SignedData payment interop without changing the locking template."""

import json
from itertools import product
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from assemble import TEMPLATE_VERSIONS
from p2pkh_sm2 import locking_script_from_public_key, sign_input
from signed_data import signed_data_signer, verify_signed_data
from sm2 import USER_ID, encode_public, fixture_sign, mul, sm3
from test_sm2 import der, der_signature, fixture
from test_sighash import chain_check
from shared.transaction import Input, Output, Transaction


SKI = der(0x80, b'\xa7' * 20)
ISSUER = der(0x30, der(0x31, der(0x30, bytes.fromhex('0603550403') + der(0x0c, b'Test issuer'))))
ISSUER_AND_SERIAL = der(0x30, ISSUER + der(0x02, b'\x01'))
OTHER_ISSUER_AND_SERIAL = der(0x30, ISSUER + der(0x02, b'\x02'))
SM3 = der(0x30, bytes.fromhex('06082a811ccf550183110500'))
SM2 = der(0x30, bytes.fromhex('06092a811ccf5501822d010500'))
SM2_WITH_SM3 = der(0x30, bytes.fromhex('06082a811ccf550183750500'))
DATA_OID = bytes.fromhex('060a2a811ccf550601040201')
SIGNED_DATA_OID = bytes.fromhex('060a2a811ccf550601040202')


def signed_data(signature, *, attached=None, sid=ISSUER_AND_SERIAL, version=2,
                outer_version=1, algorithm=SM2, signed_attrs=b'', unsigned_attrs=b'',
                metadata=b'', content_oid=DATA_OID, outer_oid=SIGNED_DATA_OID,
                digest_algorithms=SM3, signer_digest=SM3, extra_signers=b'', include_signer=True):
    content = content_oid
    if attached is not None:
        content += der(0xa0, der(0x04, attached))
    signer = (der(0x02, bytes((version,))) + sid + signer_digest + signed_attrs + algorithm
              + der(0x04, signature) + unsigned_attrs)
    signers = b''.join(sorted((der(0x30, signer) if include_signer else b'', extra_signers)))
    body = (der(0x02, bytes((outer_version,))) + der(0x31, digest_algorithms)
            + der(0x30, content) + metadata + der(0x31, signers))
    return der(0x30, outer_oid + der(0xa0, der(0x30, body)))


class SignedDataTests(unittest.TestCase):
    def test_template_witness_is_identical_for_both_sighash_families(self):
        key, _, parent, tx, _, _ = fixture()
        for flag, attached in ((0x41, False), (0x61, True)):
            with self.subTest(flag=hex(flag), attached=attached):
                def sign_raw(message, user_id):
                    return fixture_sign(1, message, 2, user_id)

                def sign_envelope(message, user_id):
                    return signed_data(der_signature(sign_raw(message, user_id)),
                                       attached=message if attached else None)

                funding = parent.serialize()
                direct = sign_input(tx, 0, funding, key, sign_raw, flag)
                adapter = signed_data_signer(sign_envelope, key, signer_identifier=ISSUER_AND_SERIAL)
                adapted = sign_input(tx, 0, funding, key, adapter, flag)
                self.assertEqual(adapted.serialize(), direct.serialize())
                chain_check(adapted, (parent,), 0)

    def test_openssl_signer_interoperates(self):
        with tempfile.TemporaryDirectory() as directory:
            private_key = str(Path(directory) / 'test-only.pem')
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'SM2', '-out', private_key], check=True)
            key = subprocess.check_output(['openssl', 'pkey', '-in', private_key, '-pubout', '-outform', 'DER'])[-65:]

            def sign_envelope(message, user_id):
                path = Path(directory) / 'message'
                path.write_bytes(message)
                signature = subprocess.check_output([
                    'openssl', 'pkeyutl', '-sign', '-rawin', '-digest', 'sm3', '-inkey', private_key,
                    '-pkeyopt', 'distid:' + user_id.decode('ascii'), '-in', str(path),
                ])
                return signed_data(signature, attached=message)

            parent = Transaction((Input(b'\xa7' * 32, 0),), (Output(1000, locking_script_from_public_key(key)),))
            tx = Transaction((Input(parent.txid_wire(), 0),), (Output(900, b'\x51'),))
            adapter = signed_data_signer(sign_envelope, key, signer_identifier=ISSUER_AND_SERIAL)
            adapted = sign_input(tx, 0, parent.serialize(), key, adapter)
            chain_check(adapted, (parent,), 0)

    @unittest.skipUnless(os.environ.get('SM2_SIGNED_DATA_SIGNER'),
                         'set SM2_SIGNED_DATA_SIGNER to the independent signer executable')
    def test_independent_gmsm_signed_data_provider(self):
        executable = os.environ['SM2_SIGNED_DATA_SIGNER']
        test_key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'

        def request(message, detached=False):
            arguments = [executable, '-message', message.hex(), '-key', test_key]
            if detached:
                arguments.append('-detached')
            return json.loads(subprocess.check_output(arguments))

        identity = request(bytes(32))
        key = bytes.fromhex(identity['public_key_hex'])
        signer_identifier = bytes.fromhex(identity['signer_identifier_hex'])
        self.assertEqual(identity['signer_version'], 2)

        for version, (flag, detached) in product(TEMPLATE_VERSIONS[1:], ((0x41, False), (0x61, True))):
            with self.subTest(template_version=version, flag=hex(flag), detached=detached):
                parent = Transaction((Input(b'\xa7' * 32, 0),),
                                     (Output(1000, locking_script_from_public_key(key, version=version)),))
                tx = Transaction((Input(parent.txid_wire(), 0),), (Output(900, b'\x51'),))

                def provider(message, user_id):
                    self.assertEqual(user_id, USER_ID)
                    response = request(message, detached)
                    self.assertEqual(bytes.fromhex(response['public_key_hex']), key)
                    self.assertEqual(bytes.fromhex(response['signer_identifier_hex']), signer_identifier)
                    self.assertEqual(response['signer_version'], 2)
                    envelope = bytes.fromhex(response['envelope_hex'])
                    self.assertEqual(verify_signed_data(
                        envelope, {signer_identifier: (key, user_id)},
                        detached_content=message if detached else None,
                    ), message)
                    return envelope

                adapter = signed_data_signer(provider, key, signer_identifier=signer_identifier)
                adapted = sign_input(tx, 0, parent.serialize(), key, adapter, flag)
                chain_check(adapted, (parent,), 0)
                if os.environ.get('REGTEST_COOKIE'):
                    from test_node import check_node
                    check_node(adapted, (parent,), 0)

    def test_rejects_wrong_authorization_or_container(self):
        message = bytes(range(32))
        key = encode_public(mul(1))
        signature = der_signature(fixture_sign(1, message, 2))
        good = signed_data(signature)
        digest_attribute = der(0x30, bytes.fromhex('06092a864886f70d010904') + der(0x31, der(0x04, sm3(message))))
        attribute_signature = der_signature(fixture_sign(1, der(0x31, digest_attribute), 2))
        variants = {
            'attached content differs': signed_data(signature, attached=bytes(32)),
            'wrong detached message': signed_data(der_signature(fixture_sign(1, bytes(32), 2))),
            'wrong SM2 ID': signed_data(der_signature(fixture_sign(1, message, 2, b'other ID'))),
            'wrong key': signed_data(der_signature(fixture_sign(2, message, 2))),
            'wrong serial': signed_data(signature, sid=OTHER_ISSUER_AND_SERIAL),
            'SKI': signed_data(signature, sid=SKI),
            'signed attributes': signed_data(attribute_signature, attached=message,
                                              signed_attrs=der(0xa0, digest_attribute)),
            'wrong algorithm': signed_data(signature, algorithm=SM3),
            'invalid signature DER': signed_data(bytes.fromhex('300702020001020101')),
            'extra signature data': signed_data(signature + b'\x00'),
            'trailing data': good + b'\x00',
            'truncated content': good[:-1],
        }
        for name, envelope in variants.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                signed_data_signer(lambda *_: envelope, key,
                                   signer_identifier=ISSUER_AND_SERIAL)(message, USER_ID)

    def test_provider_identifier_requires_valid_configuration(self):
        key = encode_public(mul(1))
        for identifier in (SKI, der(0x30, ISSUER + der(0x02, b'\x00')),
                           der(0x30, ISSUER + der(0x02, b'\x00\x01'))):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                signed_data_signer(lambda *_: None, key, signer_identifier=identifier)


if __name__ == '__main__':
    unittest.main()
