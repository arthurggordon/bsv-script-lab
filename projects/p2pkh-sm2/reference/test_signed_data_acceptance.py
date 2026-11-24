"""Finite acceptance model and clause witnesses for SM2 payment SignedData."""

from hashlib import sha256
from itertools import product
from math import prod
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from cryptography.x509 import load_der_x509_crl
from ecdsa.util import sigdecode_der
from signed_data import signed_data_signer, verify_signed_data
from sm2 import N
from test_signed_data import (
    DATA_OID, ISSUER_AND_SERIAL, OTHER_ISSUER_AND_SERIAL, SIGNED_DATA_OID,
    SKI, SM2, SM2_WITH_SM3, SM3, signed_data,
)
from test_sm2 import der


MESSAGE = bytes(range(32))
OTHER_MESSAGE = bytes(reversed(MESSAGE))
USER_ID = b'1234567812345678'
OTHER_ID = b'other user ID'
NULL = der(0x05, b'')
MESSAGE_DIGEST_OID = bytes.fromhex('06092a864886f70d010904')

CONFIGURED_VERSIONS = (1, 2)
SIGNER_VERSIONS = (1, 2, 3)
OUTER_VERSIONS = (1, 2)
CONTENTS = (None, MESSAGE, OTHER_MESSAGE)
ALGORITHMS = (SM2, SM2_WITH_SM3, SM3)
SIGNATURES = ('direct', 'attributes', 'other_key', 'other_id', 'other_message')
AXES = (CONFIGURED_VERSIONS, SIGNER_VERSIONS, OUTER_VERSIONS, CONTENTS, ALGORITHMS, SIGNATURES)
CASE_COUNT = 540

# Fields of §8 tables 2 and 3 and the signature-input rules that follow them.
TABLE_2 = ('version', 'digestAlgorithms', 'encapContentInfo', 'certificates', 'crls', 'signerInfos')
TABLE_3 = ('version', 'issuerAndSerialNumber', 'digestAlgorithm', 'signedAttrs',
           'signatureAlgorithm', 'signature', 'unsignedAttrs')
CLAUSE_EVIDENCE = {
    '5.ContentInfo': ('single_field', 'framing'),
    '6.1.CertificateRevocationLists': ('metadata', 'crl_next_update'),
    '6.3.DigestAlgorithmIdentifier': ('single_field', 'digest_set'),
    '6.4.SignatureAlgorithmIdentifier': ('payment_matrix', 'digest_set'),
    '6.5.Certificates': ('metadata', 'certificate_fields'),
    '6.6.IssuerAndSerialNumber': ('issuer', 'single_field'),
    '6.8.Version': ('payment_matrix',),
    '6.9.Attribute': ('unsigned_attribute',),
    '7.Data': ('payment_matrix', 'single_field'),
    '8.table2.version': ('payment_matrix',),
    '8.table2.digestAlgorithms': ('digest_set', 'single_field'),
    '8.table2.encapContentInfo': ('payment_matrix', 'single_field'),
    '8.table2.certificates': ('metadata', 'certificate_fields'),
    '8.table2.crls': ('metadata', 'crl_next_update'),
    '8.table2.signerInfos': ('signer_count_policy', 'verify_all_signers'),
    '8.table3.version': ('payment_matrix',),
    '8.table3.issuerAndSerialNumber': ('issuer', 'single_field'),
    '8.table3.digestAlgorithm': ('single_field',),
    '8.table3.signedAttrs': ('signed_attrs_policy', 'verify_signed_attributes'),
    '8.table3.signatureAlgorithm': ('payment_matrix',),
    '8.table3.signature': ('external_signature', 'der_scalars'),
    '8.table3.unsignedAttrs': ('metadata', 'unsigned_attribute'),
    '8.direct_signature': ('external_signature', 'payment_matrix'),
    '8.signed_attrs_signature': ('signed_attrs_policy', 'verify_signed_attributes'),
    '8.messageDigest': ('verify_signed_attributes',),
    'A.1.example': ('appendix_a1',),
    'GB/T 20518-2018.5.2.3.2.SerialNumber': ('certificate_fields',),
    'GB/T 20518-2018.5.2.3.4.Issuer': ('certificate_fields',),
    'GB/T 20518-2018.5.3.3.5.nextUpdate': ('crl_next_update',),
    'X.690.8.3.Integer': ('unsigned_attribute',),
}
COMPLETED_WITNESSES = set()


class SignedDataAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = TemporaryDirectory(prefix='sm2-signed-data-acceptance-')
        cls.addClassCleanup(temp.cleanup)
        cls.directory = Path(temp.name)
        for name in ('signer', 'other'):
            cls.openssl('genpkey', '-algorithm', 'SM2', '-out', name + '.pem')
            public = cls.openssl('pkey', '-in', name + '.pem', '-pubout')
            (cls.directory / (name + '-public.pem')).write_bytes(public)
        cls.key = cls.openssl('pkey', '-pubin', '-in', 'signer-public.pem', '-outform', 'DER')[-65:]
        other_key = cls.openssl('pkey', '-pubin', '-in', 'other-public.pem', '-outform', 'DER')[-65:]
        cls.trusted_signers = {ISSUER_AND_SERIAL: (cls.key, USER_ID),
                               OTHER_ISSUER_AND_SERIAL: (other_key, OTHER_ID)}

        digest = cls.openssl('dgst', '-sm3', '-binary', data=MESSAGE)
        cls.attribute = der(0x30, MESSAGE_DIGEST_OID + der(0x31, der(4, digest)))
        cls.attributes = der(0xa0, cls.attribute)
        cls.attribute_payload = der(0x31, cls.attribute)
        cls.signatures = {
            'direct': cls.external_signature(MESSAGE),
            'attributes': cls.external_signature(cls.attribute_payload),
            'other_key': cls.external_signature(MESSAGE, key='other'),
            'other_id': cls.external_signature(MESSAGE, user_id=OTHER_ID),
            'other_message': cls.external_signature(OTHER_MESSAGE),
        }
        r, s = sigdecode_der(cls.signatures['direct'], N)
        cls.raw_direct = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    @classmethod
    def openssl(cls, *args, data=None):
        return subprocess.run(['openssl', *args], cwd=cls.directory, input=data, capture_output=True,
                              check=True, timeout=15).stdout

    @classmethod
    def external_signature(cls, data, *, key='signer', user_id=USER_ID):
        (cls.directory / 'payload.bin').write_bytes(data)
        return cls.openssl('pkeyutl', '-sign', '-rawin', '-digest', 'sm3',
                           '-inkey', key + '.pem', '-pkeyopt', 'distid:' + user_id.decode(),
                           '-in', 'payload.bin')

    def external_verify(self, signature, data, *, key='signer', user_id=USER_ID):
        path = self.directory / 'signature.der'
        path.write_bytes(signature)
        (self.directory / 'payload.bin').write_bytes(data)
        result = subprocess.run([
            'openssl', 'pkeyutl', '-verify', '-pubin', '-rawin', '-digest', 'sm3',
            '-inkey', key + '-public.pem', '-pkeyopt', 'distid:' + user_id.decode(),
            '-sigfile', str(path), '-in', 'payload.bin',
        ], cwd=self.directory, capture_output=True, timeout=15)
        if result.returncode == 0:
            return True
        if result.returncode == 1 and b'Signature Verification Failure' in result.stdout:
            return False
        self.fail(f'OpenSSL could not verify the fixture: {result.returncode} {result.stderr!r}')

    def apply_adapter(self, envelope, version=2):
        adapter = signed_data_signer(lambda *_: envelope, self.key,
                                     signer_identifier=ISSUER_AND_SERIAL, signer_version=version)
        return adapter(MESSAGE, USER_ID)

    def test_external_signatures_bind_the_declared_payloads(self):
        inputs = {
            'direct': (MESSAGE, 'signer', USER_ID),
            'attributes': (self.attribute_payload, 'signer', USER_ID),
            'other_key': (MESSAGE, 'other', USER_ID),
            'other_id': (MESSAGE, 'signer', OTHER_ID),
            'other_message': (OTHER_MESSAGE, 'signer', USER_ID),
        }
        for name, (payload, key, user_id) in inputs.items():
            with self.subTest(payload=name):
                signature = self.signatures[name]
                self.assertTrue(self.external_verify(signature, payload, key=key, user_id=user_id))
                self.assertEqual(self.external_verify(signature, MESSAGE), name == 'direct')
        COMPLETED_WITNESSES.add('external_signature')

    def test_appendix_a1_signature_replay(self):
        path = Path(__file__).resolve().parents[1] / 'template' / 'signed-data-appendix-a1.hex'
        encoded = bytes.fromhex(path.read_text(encoding='ascii'))
        self.assertEqual(sha256(encoded).hexdigest(),
                         '42af73196f43e2b5ef62be4460b7991705e0eaccd54c42b6b1ef0248d4d40eea')
        # Offsets are printed in the official Appendix A.1 ASN.1 listing.
        self.assertEqual(encoded[24:27], b'\x02\x01\x01')
        self.assertEqual(encoded[860:863], b'\x02\x01\x01')
        for offset in (31, 987):
            self.assertEqual(encoded[offset:offset + 11], bytes.fromhex('06092a811ccf5501831101'))
        cert, message, signature = encoded[90:854], encoded[62:86], encoded[1017:]
        self.assertEqual(len(message), 24)
        self.assertEqual(len(signature), 70)
        public = self.openssl('x509', '-inform', 'DER', '-noout', '-pubkey', data=cert)
        (self.directory / 'appendix-public.pem').write_bytes(public)
        self.assertTrue(self.external_verify(signature, message, key='appendix'))
        key = self.openssl('pkey', '-pubin', '-in', 'appendix-public.pem', '-outform', 'DER')[-65:]
        sid = encoded[863:985]
        with self.assertRaisesRegex(ValueError, 'expected SignerInfo version 2'):
            verify_signed_data(encoded, {sid: (key, USER_ID)})
        # SignerInfo.version is outside the signed payload. Changing only
        # this octet reuses the published content, certificate and signature.
        version_2 = encoded[:862] + b'\x02' + encoded[863:]
        self.assertEqual(verify_signed_data(version_2, {sid: (key, USER_ID)}), message)
        for version in CONFIGURED_VERSIONS:
            adapter = signed_data_signer(lambda *_: encoded, key, signer_identifier=sid, signer_version=version)
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'expected the template transaction message'):
                adapter(message, USER_ID)
        COMPLETED_WITNESSES.add('appendix_a1')

    def test_payment_decision_exhausts_the_declared_domain(self):
        # These are the only three admissible version/algorithm pairs, with one
        # row for each of the two allowed content modes.
        expected = {
            (1, 1, 1, None, SM2, 'direct'),
            (1, 1, 1, MESSAGE, SM2, 'direct'),
            (1, 1, 1, None, SM2_WITH_SM3, 'direct'),
            (1, 1, 1, MESSAGE, SM2_WITH_SM3, 'direct'),
            (2, 2, 1, None, SM2, 'direct'),
            (2, 2, 1, MESSAGE, SM2, 'direct'),
        }
        visited, accepted = set(), set()
        self.assertEqual(prod(map(len, AXES)), CASE_COUNT)
        self.assertTrue(all(len(set(axis)) == len(axis) for axis in AXES))
        for case in product(*AXES):
            configured, signer, outer, content, algorithm, payload = case
            with self.subTest(configured=configured, signer=signer, outer=outer,
                              content=CONTENTS.index(content), algorithm=ALGORITHMS.index(algorithm),
                              payload=payload):
                self.assertTrue(all(value in axis for value, axis in zip(case, AXES, strict=True)))
                self.assertNotIn(case, visited)
                visited.add(case)
                envelope = signed_data(
                    self.signatures[payload], attached=content, version=signer, outer_version=outer,
                    algorithm=algorithm, signed_attrs=self.attributes if payload == 'attributes' else b'',
                )
                if case in expected:
                    self.assertEqual(self.apply_adapter(envelope, configured), self.raw_direct)
                    accepted.add(case)
                else:
                    with self.assertRaises(ValueError):
                        self.apply_adapter(envelope, configured)
        self.assertEqual(len(visited), CASE_COUNT)
        self.assertEqual(accepted, expected)
        COMPLETED_WITNESSES.add('payment_matrix')

    def test_single_clause_mutations_report_the_expected_failure(self):
        signature = self.signatures['direct']
        cases = (
            ('§5 ContentInfo OID', {'outer_oid': DATA_OID}, 'expected SM2 SignedData content type'),
            ('§8 table 2 digest set missing SM3', {'digest_algorithms': b''}, 'unexpected or truncated'),
            ('§8 table 2 digest set uses wrong OID', {'digest_algorithms': SM2}, 'unexpected SignedData algorithm'),
            ('§8 payment content type', {'content_oid': SIGNED_DATA_OID}, 'expected SM2 data content type'),
            ('§8 table 3 identifier form', {'sid': SKI}, 'unexpected or truncated'),
            ('pinned signer identifier', {'sid': OTHER_ISSUER_AND_SERIAL}, 'signer identifier differs'),
            ('§8 table 3 signer digest', {'signer_digest': SM2}, 'unexpected SignedData algorithm'),
            ('§8 table 3 empty signature', {'signature': b''}, 'unexpected or truncated'),
            ('§8 table 3 out-of-range scalar', {'signature': der(0x30, bytes.fromhex('020100020101'))},
             'SM2 scalar outside the curve order'),
        )
        for rule, mutation, reason in cases:
            with self.subTest(rule=rule), self.assertRaisesRegex(ValueError, reason):
                self.apply_adapter(signed_data(**({'signature': signature} | mutation)))
        COMPLETED_WITNESSES.add('single_field')

    def test_payment_digest_set_cardinality_without_wrong_oid(self):
        signature = self.signatures['direct']
        sm3_without_parameters = bytes.fromhex('300a06082a811ccf55018311')
        appendix_sm3 = bytes.fromhex('300d06092a811ccf55018311010500')
        unkeyed_without_parameters = bytes.fromhex('300b06092a811ccf5501831101')
        forms = (SM3, sm3_without_parameters, appendix_sm3, unkeyed_without_parameters)
        for outer, inner in product(forms, repeat=2):
            with self.subTest(outer=outer.hex(), inner=inner.hex()):
                envelope = signed_data(signature, digest_algorithms=outer, signer_digest=inner)
                self.assertEqual(self.apply_adapter(envelope), self.raw_direct)
        for pair in ((SM3, SM3), (SM3, sm3_without_parameters), (SM3, appendix_sm3)):
            with self.subTest(digest_pair=pair), self.assertRaisesRegex(ValueError, 'trailing or unsupported'):
                self.apply_adapter(signed_data(signature, digest_algorithms=b''.join(sorted(pair))))
        keyed_sm3 = bytes.fromhex('300d06092a811ccf55018311020500')
        for field in ('digest_algorithms', 'signer_digest'):
            with self.subTest(keyed_digest_field=field), self.assertRaisesRegex(ValueError, 'unexpected SignedData algorithm'):
                self.apply_adapter(signed_data(signature, **{field: keyed_sm3}))
        sm2_without_parameters = bytes.fromhex('300b06092a811ccf5501822d01')
        self.assertEqual(self.apply_adapter(signed_data(signature, algorithm=sm2_without_parameters)),
                         self.raw_direct)
        for field, form in (('digest_algorithms', sm3_without_parameters),
                            ('signer_digest', sm3_without_parameters),
                            ('algorithm', sm2_without_parameters)):
            for parameter, reason in ((der(0x05, b'\0'), 'invalid DER NULL'),
                                      (der(0x02, b'\x01'), 'trailing or unsupported'),
                                      (NULL + NULL, 'trailing or unsupported')):
                invalid = der(0x30, form[2:] + parameter)
                with self.subTest(field=field, parameter=parameter.hex()), self.assertRaisesRegex(ValueError, reason):
                    self.apply_adapter(signed_data(signature, **{field: invalid}))
        COMPLETED_WITNESSES.add('digest_set')

    def test_pinned_issuer_requires_der_rdn_structure(self):
        signature = self.signatures['direct']
        self.assertEqual(self.apply_adapter(signed_data(signature)), self.raw_direct)
        serial = der(0x02, b'\x01')
        cases = (
            ('empty Name', b''),
            ('NULL instead of an RDN', NULL),
            ('NULL instead of an attribute', der(0x31, NULL)),
            ('empty RDN', der(0x31, b'')),
            ('missing attribute value', der(0x31, der(0x30, bytes.fromhex('0603550403')))),
        )
        for name, rdn in cases:
            sid = der(0x30, der(0x30, rdn) + serial)
            matching_envelope = signed_data(signature, sid=sid)
            with self.subTest(issuer=name), self.assertRaisesRegex(ValueError, 'invalid DER issuer Name'):
                signed_data_signer(lambda *_: matching_envelope, self.key,
                                   signer_identifier=sid)(MESSAGE, USER_ID)
        COMPLETED_WITNESSES.add('issuer')

    def test_every_proper_prefix_and_extra_trailing_octet_is_rejected(self):
        envelope = signed_data(self.signatures['direct'], attached=MESSAGE)
        self.assertEqual(self.apply_adapter(envelope), self.raw_direct)
        for end in range(len(envelope)):
            with self.subTest(prefix=end), self.assertRaises(ValueError):
                self.apply_adapter(envelope[:end])
        for octet in range(256):
            with self.subTest(trailing=octet), self.assertRaisesRegex(ValueError, 'trailing'):
                self.apply_adapter(envelope + bytes((octet,)))
        COMPLETED_WITNESSES.add('framing')

    def test_der_length_and_integer_boundaries(self):
        body = b'\x02\x01\x01'
        for invalid, reason in (
            (bytes.fromhex('3080') + body + b'\0\0', 'invalid DER length'),
            (bytes.fromhex('308103') + body, 'non-minimal DER length'),
            (bytes.fromhex('30820003') + body, 'invalid DER length'),
            (bytes.fromhex('308302'), 'invalid DER length'),
        ):
            with self.subTest(invalid=invalid.hex()), self.assertRaisesRegex(ValueError, reason):
                self.apply_adapter(invalid)

        for integer in (b'', b'\x80', b'\0\x01', b'\0', N.to_bytes(33, 'big')):
            for scalars in ((integer, b'\x01'), (b'\x01', integer)):
                signature = der(0x30, b''.join(der(2, scalar) for scalar in scalars))
                with self.subTest(scalars=scalars), self.assertRaisesRegex(ValueError, 'SM2 scalar'):
                    self.apply_adapter(signed_data(signature))
        COMPLETED_WITNESSES.add('der_scalars')

    def test_standard_signed_attributes_and_multiple_signers_are_outside_payment_profile(self):
        self.assertTrue(self.external_verify(self.signatures['attributes'], self.attribute_payload))
        wrong_digest = self.openssl('dgst', '-sm3', '-binary', data=OTHER_MESSAGE)
        wrong_attribute = der(0x30, MESSAGE_DIGEST_OID + der(0x31, der(4, wrong_digest)))
        wrong_payload = der(0x31, wrong_attribute)
        wrong_signature = self.external_signature(wrong_payload)
        self.assertTrue(self.external_verify(wrong_signature, wrong_payload))
        for attribute, signature in ((self.attribute, self.signatures['attributes']),
                                     (wrong_attribute, wrong_signature)):
            attributes = signed_data(signature, attached=MESSAGE, signed_attrs=der(0xa0, attribute))
            with self.subTest(correct_content_digest=attribute == self.attribute):
                with self.assertRaisesRegex(ValueError, 'signedAttrs'):
                    self.apply_adapter(attributes)
        COMPLETED_WITNESSES.add('signed_attrs_policy')

        direct = self.signatures['direct']
        self.assertEqual(self.apply_adapter(signed_data(direct, attached=MESSAGE)), self.raw_direct)
        with self.assertRaisesRegex(ValueError, 'unexpected or truncated'):
            self.apply_adapter(signed_data(direct, attached=MESSAGE, include_signer=False))
        self.assertTrue(self.external_verify(direct, MESSAGE))
        self.assertTrue(self.external_verify(self.signatures['other_key'], MESSAGE, key='other'))
        second = der(0x30, b'\x02\x01\x02' + OTHER_ISSUER_AND_SERIAL + SM3 + SM2
                     + der(0x04, self.signatures['other_key']))
        two_signers = signed_data(self.signatures['direct'], attached=MESSAGE, extra_signers=second)
        with self.assertRaisesRegex(ValueError, 'trailing or unsupported'):
            self.apply_adapter(two_signers)
        COMPLETED_WITNESSES.add('signer_count_policy')

    def test_verify_all_signers_and_content_modes(self):
        message = b'Independent SignerInfo entries with an application content type.'
        content_type = der(0x06, bytes.fromhex('2a0304'))
        direct = self.external_signature(message)
        second = self.external_signature(message, key='other', user_id=OTHER_ID)
        self.assertTrue(self.external_verify(second, message, key='other', user_id=OTHER_ID))

        def second_entry(signature):
            return der(0x30, b'\x02\x01\x02' + OTHER_ISSUER_AND_SERIAL + SM3 + SM2
                       + der(0x04, signature))

        for attached in (None, message):
            for extra in (b'', second_entry(second)):
                with self.subTest(attached=attached is not None, multiple_signers=bool(extra)):
                    envelope = signed_data(direct, attached=attached, content_oid=content_type,
                                           extra_signers=extra)
                    detached = message if attached is None else None
                    self.assertEqual(verify_signed_data(envelope, self.trusted_signers,
                                                        detached_content=detached), message)

        digest = self.openssl('dgst', '-sm3', '-binary', data=message)
        attribute = der(0x30, MESSAGE_DIGEST_OID + der(0x31, der(0x04, digest)))
        attributes_signature = self.external_signature(der(0x31, attribute))
        sm3_unkeyed = bytes.fromhex('300b06092a811ccf5501831101')
        digests = b''.join(sorted((SM3, sm3_unkeyed)))
        options = {'attached': message, 'signed_attrs': der(0xa0, attribute),
                   'extra_signers': second_entry(second), 'digest_algorithms': digests}
        mixed = signed_data(attributes_signature, **options)
        self.assertEqual(verify_signed_data(mixed, self.trusted_signers), message)
        with self.assertRaisesRegex(ValueError, 'out of order'):
            unsorted_digests = b''.join(sorted((SM3, sm3_unkeyed), reverse=True))
            verify_signed_data(signed_data(attributes_signature, **(options | {'digest_algorithms': unsorted_digests})),
                               self.trusted_signers)
        with self.assertRaisesRegex(ValueError, 'expected SM3 in digestAlgorithms'):
            verify_signed_data(signed_data(direct, attached=message, digest_algorithms=b''), self.trusted_signers)

        empty_signature = self.external_signature(b'')
        self.assertEqual(verify_signed_data(signed_data(empty_signature, attached=b''), self.trusted_signers), b'')
        self.assertEqual(verify_signed_data(signed_data(empty_signature), self.trusted_signers,
                                            detached_content=b''), b'')
        first_entry = der(0x30, b'\x02\x01\x02' + ISSUER_AND_SERIAL + SM3 + SM2 + der(0x04, direct))
        unsorted_signers = b''.join(sorted((first_entry, second_entry(second)), reverse=True))
        with self.assertRaisesRegex(ValueError, 'out of order'):
            envelope = signed_data(direct, attached=message, include_signer=False, extra_signers=unsorted_signers)
            verify_signed_data(envelope, self.trusted_signers)

        wrong_second = self.external_signature(message, key='other', user_id=USER_ID)
        with self.assertRaisesRegex(ValueError, 'invalid SignedData signature'):
            verify_signed_data(signed_data(direct, attached=message, extra_signers=second_entry(wrong_second)),
                               self.trusted_signers)
        with self.assertRaisesRegex(ValueError, 'untrusted SignedData signer identifier'):
            envelope = signed_data(direct, attached=message, extra_signers=second_entry(second))
            verify_signed_data(envelope, {ISSUER_AND_SERIAL: (self.key, USER_ID)})
        with self.assertRaisesRegex(ValueError, 'at least one signer'):
            verify_signed_data(signed_data(direct, attached=message, include_signer=False), {})
        with self.assertRaisesRegex(ValueError, 'requires detached content'):
            verify_signed_data(signed_data(direct), self.trusted_signers)
        with self.assertRaisesRegex(ValueError, 'differs from encapsulated'):
            verify_signed_data(signed_data(direct, attached=message), self.trusted_signers,
                               detached_content=OTHER_MESSAGE)
        COMPLETED_WITNESSES.add('verify_all_signers')

    def test_verify_signed_attributes_and_content_digest(self):
        digest = self.openssl('dgst', '-sm3', '-binary', data=MESSAGE)
        alternate_attr = der(0x30, der(0x06, b'\x2a\x03') + der(0x31, der(0x04, b'other attribute')))
        attrs = b''.join(sorted((self.attribute, alternate_attr)))
        valid = self.external_signature(der(0x31, attrs))
        for attached in (MESSAGE, None):
            with self.subTest(attached=attached is not None):
                envelope = signed_data(valid, attached=attached, signed_attrs=der(0xa0, attrs))
                self.assertEqual(verify_signed_data(envelope, self.trusted_signers,
                                                    detached_content=MESSAGE if attached is None else None), MESSAGE)

        def digest_attribute(*values):
            return der(0x30, MESSAGE_DIGEST_OID + der(0x31, b''.join(sorted(values))))

        wrong_digest = self.openssl('dgst', '-sm3', '-binary', data=OTHER_MESSAGE)
        cases = (
            (b'', 'exactly one messageDigest'),
            (alternate_attr, 'exactly one messageDigest'),
            (self.attribute * 2, 'exactly one messageDigest'),
            (digest_attribute(), 'exactly one messageDigest'),
            (digest_attribute(der(4, digest), der(4, wrong_digest)), 'exactly one messageDigest'),
            (digest_attribute(der(4, wrong_digest)), 'differs from SM3'),
            (digest_attribute(der(4, digest[:-1])), 'differs from SM3'),
            (digest_attribute(der(0x16, b'not an octet string')), 'unexpected or truncated'),
            (b''.join(sorted((self.attribute, alternate_attr), reverse=True)), 'out of order'),
        )
        for members, reason in cases:
            payload = der(0x31, members)
            signature = self.external_signature(payload)
            self.assertTrue(self.external_verify(signature, payload))
            envelope = signed_data(signature, attached=MESSAGE, signed_attrs=der(0xa0, members))
            with self.subTest(attrs=members.hex()), self.assertRaisesRegex(ValueError, reason):
                verify_signed_data(envelope, self.trusted_signers)
        wrong_tag = self.external_signature(der(0xa0, attrs))
        with self.assertRaisesRegex(ValueError, 'invalid SignedData signature'):
            envelope = signed_data(wrong_tag, attached=MESSAGE, signed_attrs=der(0xa0, attrs))
            verify_signed_data(envelope, self.trusted_signers)
        with self.assertRaisesRegex(ValueError, 'differs from SM3'):
            envelope = signed_data(valid, signed_attrs=der(0xa0, attrs))
            verify_signed_data(envelope, self.trusted_signers, detached_content=OTHER_MESSAGE)
        COMPLETED_WITNESSES.add('verify_signed_attributes')

    def test_embedded_certificate_issuer_and_serial_boundaries(self):
        cases = (
            ('/CN=Test issuer', '1', None),
            ('/CN=Test issuer', '0x7f' + 'ff' * 19, None),
            ('/', '1', 'empty certificate issuer'),
            ('/CN=Test issuer', '0', 'positive certificate serial number'),
            ('/CN=Test issuer', '0x80' + '00' * 19, 'at most 20 octets'),
            ('/CN=Test issuer', '0x01' + '00' * 20, 'at most 20 octets'),
        )
        for issuer, serial, reason in cases:
            cert = self.openssl('req', '-new', '-x509', '-key', 'signer.pem', '-sm3', '-subj', issuer,
                                '-set_serial', serial, '-days', '1', '-outform', 'DER')
            printed = self.openssl('x509', '-inform', 'DER', '-serial', '-noout', data=cert)
            self.assertEqual(int(printed.strip().removeprefix(b'serial='), 16), int(serial, 0))
            envelope = signed_data(self.signatures['direct'], metadata=der(0xa0, cert))
            with self.subTest(issuer=issuer, serial=serial):
                if reason is None:
                    self.assertEqual(self.apply_adapter(envelope), self.raw_direct)
                else:
                    with self.assertRaisesRegex(ValueError, 'invalid SignedData certificates: .*' + reason):
                        self.apply_adapter(envelope)
        COMPLETED_WITNESSES.add('certificate_fields')

    def test_optional_metadata_exhausts_the_declared_domain(self):
        self.openssl('req', '-new', '-x509', '-key', 'signer.pem', '-sm3', '-subj', '/CN=Test issuer',
                     '-set_serial', '1', '-days', '1', '-out', 'issuer.pem')
        cert = self.openssl('x509', '-in', 'issuer.pem', '-outform', 'DER')
        self.openssl('x509', '-inform', 'DER', '-noout', data=cert)
        (self.directory / 'index.txt').touch()
        (self.directory / 'ca.cnf').write_text(
            '[ca]\ndefault_ca = local\n[local]\ndatabase = index.txt\n'
            'certificate = issuer.pem\nprivate_key = signer.pem\n'
            'default_md = sm3\ndefault_crl_days = 1\n',
            encoding='ascii',
        )
        crl_pem = self.openssl('ca', '-gencrl', '-config', 'ca.cnf',
                               '-crl_lastupdate', '260101000000Z', '-crl_nextupdate', '260102000000Z')
        crl = self.openssl('crl', '-outform', 'DER', data=crl_pem)
        self.openssl('crl', '-inform', 'DER', '-noout', data=crl)
        unsigned_attribute = der(0x30, bytes.fromhex('06092a864886f70d010902')
                                 + der(0x31, der(0x16, b'Test metadata')))
        states = ('absent', 'empty', 'valid', 'wrong_type')
        axes = (CONFIGURED_VERSIONS, (None, MESSAGE), states, states, states)
        fields = (
            ('certificates', 0xa0, cert),
            ('crls', 0xa1, crl),
            ('unsignedAttrs', 0xa1, unsigned_attribute),
        )
        accepted = set()
        visited = set()
        self.assertTrue(all(len(set(axis)) == len(axis) for axis in axes))
        self.assertEqual(prod(map(len, axes)), 256)
        for case in product(*axes):
            version, content, *field_states = case
            with self.subTest(version=version, attached=content is not None, states=field_states):
                self.assertTrue(all(value in axis for value, axis in zip(case, axes, strict=True)))
                self.assertNotIn(case, visited)
                visited.add(case)
                metadata = []
                invalid = []
                for (name, tag, valid_member), state in zip(fields, field_states, strict=True):
                    member = {'empty': b'', 'valid': valid_member, 'wrong_type': NULL}.get(state)
                    metadata.append(b'' if member is None else der(tag, member))
                    if state == 'wrong_type' or (name == 'unsignedAttrs' and state == 'empty'):
                        invalid.append(name)
                envelope = signed_data(self.signatures['direct'], attached=content, version=version,
                                       metadata=metadata[0] + metadata[1], unsigned_attrs=metadata[2])
                if invalid:
                    with self.assertRaisesRegex(ValueError, 'invalid SignedData ' + invalid[0]):
                        self.apply_adapter(envelope, version)
                else:
                    self.assertEqual(self.apply_adapter(envelope, version), self.raw_direct)
                    accepted.add(case)

        self.assertEqual(len(visited), 256)
        allowed = ('absent', 'empty', 'valid')
        self.assertEqual(accepted, set(product(*axes[:2], allowed, allowed, ('absent', 'valid'))))
        self.assertEqual(len(accepted), 72)

        for field, tag, member in (
            ('certificates', 0xa0, der(0x30, b'')),
            ('certificates', 0xa0, crl),
            ('crls', 0xa1, der(0x30, b'')),
            ('crls', 0xa1, cert),
        ):
            with self.subTest(wrong_schema=field), self.assertRaisesRegex(ValueError, 'invalid SignedData ' + field):
                self.apply_adapter(signed_data(self.signatures['direct'], metadata=der(tag, member)))
        COMPLETED_WITNESSES.add('metadata')

        issued = load_der_x509_crl(crl)
        tbs = issued.tbs_certlist_bytes
        next_update = der(0x17, b'260102000000Z')
        self.assertEqual(tbs.count(next_update), 1)
        # This CRL contains no entries or extensions and uses short DER lengths.
        self.assertLess(tbs[1], 128)
        modified_tbs = der(0x30, tbs[2:].replace(next_update, b'', 1))
        signature = self.external_signature(modified_tbs)
        self.assertTrue(self.external_verify(signature, modified_tbs))
        signature_algorithm = bytes.fromhex('300a06082a811ccf55018375')
        without_next_update = der(0x30, modified_tbs + signature_algorithm + der(0x03, b'\0' + signature))
        self.assertIsNotNone(issued.next_update_utc)
        self.assertIsNone(load_der_x509_crl(without_next_update).next_update_utc)
        for version in CONFIGURED_VERSIONS:
            envelope = signed_data(self.signatures['direct'], version=version,
                                   metadata=der(0xa1, without_next_update))
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'invalid SignedData crls: missing CRL nextUpdate'):
                self.apply_adapter(envelope, version)
        COMPLETED_WITNESSES.add('crl_next_update')

    def test_unsigned_attribute_der_structure_and_order(self):
        oid = der(0x06, bytes.fromhex('2a0304'))
        low, high = der(0x04, b'a'), bytes.fromhex('9f1f0162')
        attribute = der(0x30, oid + der(0x31, low + high))
        other_attribute = der(0x30, oid + der(0x31, der(0x04, b'z')))
        valid = b''.join(sorted((attribute, other_attribute)))

        def envelope(attributes):
            return signed_data(self.signatures['direct'], unsigned_attrs=der(0xa1, attributes))

        self.assertEqual(self.apply_adapter(envelope(valid)), self.raw_direct)
        for integer in (b'\x00', b'\x7f', b'\x00\x80', b'\xff', b'\xff\x7f'):
            node = der(0x30, der(0x02, integer))
            self.assertEqual(self.apply_adapter(envelope(der(0x30, oid + der(0x31, node)))),
                             self.raw_direct)
        for boolean in (b'\x00', b'\xff'):
            nested = der(0x30, der(0x01, boolean))
            self.assertEqual(self.apply_adapter(envelope(der(0x30, oid + der(0x31, nested)))),
                             self.raw_direct)
        cases = (
            ('attribute SET order', b''.join(sorted((attribute, other_attribute), reverse=True)),
             'DER SET OF members out of order'),
            ('attribute value SET order', der(0x30, oid + der(0x31, high + low)), 'DER SET OF members out of order'),
            ('OID with redundant base-128 octet', der(0x30, der(0x06, b'\x2a\x80\x01') + der(0x31, low)),
             'invalid DER attribute OID'),
            ('wrong attrValues tag', der(0x30, oid + der(0x30, low)), 'unexpected or truncated'),
            ('trailing attribute child', der(0x30, oid + der(0x31, low) + NULL), 'trailing or unsupported'),
            ('non-minimal high tag', der(0x30, oid + der(0x31, bytes.fromhex('9f1e00'))), 'invalid DER tag'),
            ('truncated value', der(0x30, oid + der(0x31, bytes.fromhex('0402ff'))), 'truncated DER content'),
            ('two-octet BOOLEAN', der(0x30, oid + der(0x31, der(0x01, b'\x00\xff'))), 'invalid DER BOOLEAN'),
            ('nested non-canonical TRUE', der(0x30, oid + der(0x31, der(0x30, der(0x01, b'\x01')))),
             'invalid DER BOOLEAN'),
        )
        for integer in (b'', b'\x00\x01', b'\xff\x80'):
            for node in (der(0x02, integer), der(0x30, der(0x02, integer))):
                malformed = der(0x30, oid + der(0x31, node))
                with self.subTest(integer=integer.hex(), node=node.hex()), self.assertRaisesRegex(ValueError, 'invalid DER INTEGER'):
                    self.apply_adapter(envelope(malformed))
        for name, attributes, reason in cases:
            with self.subTest(rule=name), self.assertRaisesRegex(ValueError, 'invalid SignedData unsignedAttrs: ' + reason):
                self.apply_adapter(envelope(attributes))
        COMPLETED_WITNESSES.add('unsigned_attribute')


def check_traceability():
    case = unittest.TestCase()
    table_fields = {f'8.table{table}.{field}' for table, fields in ((2, TABLE_2), (3, TABLE_3))
                    for field in fields}
    case.assertEqual({key for key in CLAUSE_EVIDENCE if key.startswith('8.table')}, table_fields)
    case.assertTrue(all(CLAUSE_EVIDENCE.values()))
    case.assertEqual(COMPLETED_WITNESSES, {witness for entries in CLAUSE_EVIDENCE.values() for witness in entries})


def load_tests(loader, tests, pattern):
    COMPLETED_WITNESSES.clear()
    tests.addTest(unittest.FunctionTestCase(check_traceability, description='SignedData clause traceability'))
    return tests


if __name__ == '__main__':
    unittest.main()
