"""Finite acceptance model and clause witnesses for SM2 payment SignedData."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from itertools import product
from math import prod
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from asn1crypto.core import Integer, ObjectIdentifier, SetOf
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Name, NameAttribute, ReasonFlags, load_der_x509_certificate, load_der_x509_crl
from cryptography.x509.oid import NameOID
from ecdsa.der import read_length, remove_integer, remove_sequence
from ecdsa.util import sigdecode_der
from signed_data import AmbiguousCertificateIssuer, MissingAttributeSchema, MissingExtensionSchema
from signed_data import merge_crl_revocations
from signed_data import signed_data_signer, validate_crl_pair, validate_crl_series
from signed_data import validate_signed_data_format, verify_crl_signature, verify_signed_data
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
X509_SM2_OID = bytes.fromhex('06082a811ccf55018375')

SIGNER_VERSIONS = (1, 2, 3)
OUTER_VERSIONS = (1, 2)
CONTENTS = (None, MESSAGE, OTHER_MESSAGE)
ALGORITHMS = (SM2, SM2_WITH_SM3, SM3)
SIGNATURES = ('direct', 'attributes', 'other_key', 'other_id', 'other_message')
AXES = (SIGNER_VERSIONS, OUTER_VERSIONS, CONTENTS, ALGORITHMS, SIGNATURES)
CASE_COUNT = 270

# Fields of §8 tables 2 and 3 and the signature-input rules that follow them.
TABLE_2 = ('version', 'digestAlgorithms', 'encapContentInfo', 'certificates', 'crls', 'signerInfos')
TABLE_3 = ('version', 'issuerAndSerialNumber', 'digestAlgorithm', 'signedAttrs',
           'signatureAlgorithm', 'signature', 'unsignedAttrs')
CLAUSE_EVIDENCE = {
    '5.ContentInfo': ('single_field', 'framing'),
    '6.1.CertificateRevocationLists': ('metadata', 'crl_next_update', 'x509_algorithms'),
    '6.3.DigestAlgorithmIdentifier': ('single_field', 'digest_set', 'envelope_parameters'),
    '6.4.SignatureAlgorithmIdentifier': ('payment_matrix', 'digest_set', 'envelope_parameters'),
    '6.5.Certificates': ('metadata', 'certificate_fields', 'x509_algorithms'),
    '6.6.IssuerAndSerialNumber': ('issuer', 'single_field'),
    '6.8.Version': ('payment_matrix', 'version_octet'),
    '6.9.Attribute': ('unsigned_attribute', 'open_value_der', 'attribute_schemas'),
    '7.Data': ('payment_matrix', 'single_field'),
    '8.table2.version': ('payment_matrix', 'version_octet'),
    '8.table2.digestAlgorithms': ('digest_set', 'single_field'),
    '8.table2.encapContentInfo': ('payment_matrix', 'single_field'),
    '8.table2.certificates': ('metadata', 'certificate_fields', 'x509_algorithms', 'x509_parameters',
                              'x509_time', 'x509_signature', 'x509_extensions'),
    '8.table2.crls': ('metadata', 'crl_next_update', 'x509_algorithms', 'x509_parameters',
                      'x509_time', 'x509_signature', 'x509_extensions'),
    '8.table2.signerInfos': ('signer_count_policy', 'verify_all_signers', 'format_only'),
    '8.table3.version': ('payment_matrix', 'version_octet'),
    '8.table3.issuerAndSerialNumber': ('issuer', 'single_field'),
    '8.table3.digestAlgorithm': ('single_field',),
    '8.table3.signedAttrs': ('signed_attrs_policy', 'verify_signed_attributes', 'open_value_der', 'open_value_forms'),
    '8.table3.signatureAlgorithm': ('payment_matrix',),
    '8.table3.signature': ('external_signature', 'der_scalars'),
    '8.table3.unsignedAttrs': ('metadata', 'unsigned_attribute', 'open_value_der', 'open_value_forms'),
    '8.direct_signature': ('external_signature', 'payment_matrix'),
    '8.signed_attrs_signature': ('signed_attrs_policy', 'verify_signed_attributes', 'signed_attrs_encoding'),
    '8.messageDigest': ('verify_signed_attributes',),
    'A.1.example': ('appendix_a1',),
    'GB/T 20518-2018.5.2.2.SM2ParametersAndSignatureValue': ('x509_parameters', 'x509_signature'),
    'GB/T 20518-2018.5.2.2.VersionDependencies': ('x509_extensions',),
    'GB/T 20518-2018.5.2.4.1.Extensions': ('x509_extensions', 'extension_schemas'),
    'GB/T 20518-2018.5.2.3.6.Subject': ('certificate_profile',),
    'GB/T 20518-2018.5.2.4.2.2.AuthorityKeyIdentifier': ('certificate_profile',),
    'GB/T 20518-2018.5.2.4.2.3.SubjectKeyIdentifier': ('certificate_profile',),
    'GB/T 20518-2018.5.2.4.2.4.KeyUsage': ('certificate_profile',),
    'GB/T 20518-2018.5.2.4.2.8.PolicyMappings': ('certificate_profile', 'certificate_constraints'),
    'GB/T 20518-2018.5.2.4.2.9.SubjectAltName': ('certificate_profile', 'certificate_extension_shapes'),
    'GB/T 20518-2018.5.2.4.2.10.IssuerAltName': ('certificate_extension_shapes',),
    'GB/T 20518-2018.5.2.4.2.12.BasicConstraints': ('certificate_profile',),
    'GB/T 20518-2018.5.2.4.2.13.NameConstraints': ('certificate_profile', 'certificate_constraints'),
    'GB/T 20518-2018.5.2.4.2.14.PolicyConstraints': ('certificate_constraints',),
    'GB/T 20518-2018.5.2.4.2.15.CRLDistPointsSyntax': ('certificate_extension_shapes',),
    'GB/T 20518-2018.5.2.4.2.17.FreshestCRL': ('certificate_extension_shapes',),
    'GB/T 20518-2018.5.2.4.2.19-22.IdentificationNumbers': ('certificate_identification_numbers',),
    'GB/T 20518-2018.5.2.4.3.2-3.InformationAccess': ('certificate_extension_shapes',),
    'GB/T 20518-2018.5.2.3.2.SerialNumber': ('certificate_fields',),
    'GB/T 20518-2018.5.2.3.3.Signature': ('x509_algorithms',),
    'GB/T 20518-2018.5.2.3.4.Issuer': ('certificate_fields',),
    'GB/T 20518-2018.5.3.3.2.Signature': ('x509_algorithms',),
    'GB/T 20518-2018.5.3.3.3.CRLIssuer': ('crl_field_encoding',),
    'GB/T 20518-2018.5.3.4.1-5.CRLExtensionProfile': ('crl_profile',),
    'GB/T 20518-2018.5.3.4.3.CRLNumberSequence': ('crl_series', 'crl_pair', 'crl_published_state'),
    'GB/T 20518-2018.5.3.4.4.DeltaBaseNumber': ('crl_profile', 'crl_pair'),
    'GB/T 20518-2018.5.3.4.5.IssuingDistributionPoint': ('crl_field_encoding',),
    'GB/T 20518-2018.5.3.4.6-7.CRLAndEntryExtensions': ('crl_entry_profile',),
    'GB/T 20518-2018.5.2.3.5.2.ValidityTime': ('x509_time',),
    'GB/T 20518-2018.5.3.2.SM2ParametersAndSignatureValue': ('x509_parameters', 'x509_signature'),
    'GB/T 20518-2018.5.3.3.4.thisUpdate': ('x509_time',),
    'GB/T 20518-2018.5.3.3.5.nextUpdate': ('crl_next_update', 'x509_time'),
    'GB/T 20518-2018.5.3.3.6.RevokedCertificates': ('crl_field_encoding',),
    'GB/T 20518-2018.5.3.2.ExtensionVersionDependencies': ('x509_extensions',),
    'RFC 5280.5.2.3.CRLNumbers': ('crl_profile', 'crl_series'),
    'RFC 5280.5.2.4.DeltaCombinationMetadata': ('crl_pair',),
    'RFC 5280.5.2.4.LocalCRLMetadata': ('crl_revocation_merge',),
    'RFC 5280.5.3.3.IndirectCRLEntryIssuer': ('crl_indirect_issuer', 'crl_merge_rejections'),
    'RFC 5280.6.3.3.c.AuthorityKeyIdentifier': ('crl_merge_rejections',),
    'RFC 5280.6.3.3.f-h.CRLIssuerKeyAndSignature': ('crl_signature_authentication', 'crl_openssl_state'),
    'GB/T 20518-2018.5.3.4.1.CRLIssuerKeyIdentifier': ('crl_signer_identifier',),
    'GB/T 35276-2017.8.1-8.2.CRLSM2SignerID': ('crl_signature_authentication',),
    'RFC 5280.6.3.3.i-k.RevocationState': ('crl_revocation_merge', 'crl_indirect_issuer', 'crl_openssl_state'),
    'RFC 5280.7.1-7.3.CRLIssuerNameMatching': ('crl_pair',),
    'X.690.8.3.Integer': ('unsigned_attribute',),
    'X.690.8.4.Enumerated': ('open_value_forms',),
    'X.690.8.6.2.BitString': ('open_value_der',),
    'X.690.8.19.ObjectIdentifier': ('open_value_der',),
    'X.690.8.20.RelativeObjectIdentifier': ('open_value_forms',),
    'X.690.8.9-8.12.SequenceAndSet': ('open_value_forms',),
    'X.690.8.23.10.UTF8String': ('open_value_forms',),
    'X.690.10.2.StringEncodingForms': ('open_value_der', 'open_value_forms'),
    'X.690.11.2.1.UnusedBits': ('open_value_der',),
    'X.690.11.5.DefaultComponents': ('x509_extensions', 'crl_field_encoding'),
    'X.690.11.7-11.8.TimeEncoding': ('open_value_forms',),
}
COMPLETED_WITNESSES = set()


def x509_signed_parts(encoded):
    outer, extra = remove_sequence(encoded)
    if extra:
        raise AssertionError('trailing data in the OpenSSL X.509 fixture')
    body, outer_fields = remove_sequence(outer)
    algorithm, _ = remove_sequence(outer_fields)
    return body, algorithm


def encoded_fields(content):
    while content:
        size, width = read_length(content[1:])
        field_end = 1 + width + size
        if field_end > len(content):
            raise AssertionError('truncated field in the OpenSSL fixture')
        yield content[:field_end]
        content = content[field_end:]


def x509_extension(oid, value, *, critical=False):
    critical_field = der(0x01, b'\xff') if critical else b''
    return der(0x30, ObjectIdentifier(oid).dump() + critical_field + der(0x04, value))


def common_name_rdn(value):
    return der(0x31, der(0x30, ObjectIdentifier('2.5.4.3').dump() + der(0x0c, value)))


def review_revoked_entry(serial, date, *, reason=None, invalidity=None, issuers=(),
                         critical_issuer=True, extra_extensions=b''):
    extensions = extra_extensions
    if reason is not None:
        extensions += x509_extension('2.5.29.21', der(0x0a, bytes((reason,))))
    if invalidity is not None:
        extensions += x509_extension('2.5.29.24', der(0x18, invalidity))
    if issuers:
        extensions += x509_extension('2.5.29.29', der(0x30, b''.join(issuers)), critical=critical_issuer)
    entry = Integer(serial).dump() + der(0x17, date)
    return der(0x30, entry + (der(0x30, extensions) if extensions else b''))


class SignedDataFixtures(unittest.TestCase):
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

    @classmethod
    def external_verify(cls, signature, data, *, key='signer', user_id=USER_ID):
        path = cls.directory / 'signature.der'
        path.write_bytes(signature)
        (cls.directory / 'payload.bin').write_bytes(data)
        result = subprocess.run([
            'openssl', 'pkeyutl', '-verify', '-pubin', '-rawin', '-digest', 'sm3',
            '-inkey', key + '-public.pem', '-pkeyopt', 'distid:' + user_id.decode(),
            '-sigfile', str(path), '-in', 'payload.bin',
        ], cwd=cls.directory, capture_output=True, timeout=15)
        if result.returncode == 0:
            return True
        if result.returncode == 1 and b'Signature Verification Failure' in result.stdout:
            return False
        raise AssertionError(f'OpenSSL could not verify the fixture: {result.returncode} {result.stderr!r}')

    @classmethod
    def apply_adapter(cls, envelope):
        adapter = signed_data_signer(lambda *_: envelope, cls.key, signer_identifier=ISSUER_AND_SERIAL)
        return adapter(MESSAGE, USER_ID)

    @classmethod
    def verify_attached(cls, envelope):
        return verify_signed_data(envelope, cls.trusted_signers)

    @classmethod
    def issue_certificate_and_crl(cls, *, version_2_crl=False):
        cls.openssl('req', '-new', '-x509', '-key', 'signer.pem', '-sm3', '-subj', '/CN=Test issuer',
                    '-set_serial', '1', '-days', '1', '-out', 'issuer.pem')
        cert = cls.openssl('x509', '-in', 'issuer.pem', '-outform', 'DER')
        cls.openssl('x509', '-inform', 'DER', '-noout', data=cert)
        (cls.directory / 'index.txt').touch()
        config = (
            '[ca]\ndefault_ca = local\n[local]\ndatabase = index.txt\n'
            'certificate = issuer.pem\nprivate_key = signer.pem\n'
            'default_md = sm3\ndefault_crl_days = 1\n'
        )
        if version_2_crl:
            (cls.directory / 'crlnumber').write_text('01\n', encoding='ascii')
            config += 'crlnumber = crlnumber\n'
        (cls.directory / 'ca.cnf').write_text(config, encoding='ascii')
        crl_pem = cls.openssl('ca', '-gencrl', '-config', 'ca.cnf',
                              '-crl_lastupdate', '260101000000Z', '-crl_nextupdate', '260102000000Z')
        crl = cls.openssl('crl', '-outform', 'DER', data=crl_pem)
        cls.openssl('crl', '-inform', 'DER', '-noout', data=crl)
        return cert, crl


class SignedDataAcceptance(SignedDataFixtures):

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
        tbs, outer_algorithm = x509_signed_parts(cert)
        self.assertEqual(tbs[:5], bytes.fromhex('a003020102'))  # Explicit X.509 v3.
        _, after_serial = remove_integer(tbs[5:])
        inner_algorithm, _ = remove_sequence(after_serial)
        self.assertEqual(inner_algorithm, X509_SM2_OID + NULL)
        self.assertEqual(outer_algorithm, X509_SM2_OID + NULL)
        public = self.openssl('x509', '-inform', 'DER', '-noout', '-pubkey', data=cert)
        (self.directory / 'appendix-public.pem').write_bytes(public)
        self.assertTrue(self.external_verify(signature, message, key='appendix'))
        COMPLETED_WITNESSES.add('appendix_a1')

    def test_both_entry_points_enforce_the_standard_version_octets(self):
        signature = self.signatures['direct']
        self.assertTrue(self.external_verify(signature, MESSAGE))
        current = signed_data(signature, attached=MESSAGE)
        self.assertEqual(self.apply_adapter(current), self.raw_direct)
        self.assertEqual(verify_signed_data(current, self.trusted_signers), MESSAGE)
        for changed, delta, error in (
            (signed_data(signature, attached=MESSAGE, version=1), (2, 1), 'expected SignerInfo version 2'),
            (signed_data(signature, attached=MESSAGE, outer_version=2), (1, 2), 'unsupported SignedData version'),
        ):
            self.assertEqual([(old, new) for old, new in zip(current, changed, strict=True) if old != new], [delta])
            for entry_point in (self.apply_adapter, lambda envelope: verify_signed_data(envelope, self.trusted_signers)):
                with self.subTest(delta=delta, entry_point=entry_point.__name__), self.assertRaisesRegex(ValueError, error):
                    entry_point(changed)
        COMPLETED_WITNESSES.add('version_octet')

    def test_format_only_signer_cardinality_and_independent_signature_checks(self):
        signature = self.signatures['direct']
        for content, algorithms in product((None, b'', MESSAGE), (b'', SM3)):
            with self.subTest(content=content, digest_algorithms=bool(algorithms)):
                envelope = signed_data(signature, attached=content, include_signer=False, digest_algorithms=algorithms)
                validate_signed_data_format(envelope)
                with self.assertRaisesRegex(ValueError, 'at least one signer'):
                    verify_signed_data(envelope, {}, detached_content=MESSAGE if content is None else None)
                with self.assertRaises(ValueError):
                    self.apply_adapter(envelope)
                self.assertEqual(envelope[-2:], b'\x31\x00')
                with self.assertRaises(ValueError):
                    validate_signed_data_format(envelope[:-2] + b'\x30\x00')
        with self.assertRaisesRegex(ValueError, 'expected SM3 in digestAlgorithms'):
            validate_signed_data_format(signed_data(signature, attached=MESSAGE, digest_algorithms=b''))

        two_signers = signed_data(signature, attached=MESSAGE, extra_signers=der(
            0x30, b'\x02\x01\x02' + OTHER_ISSUER_AND_SERIAL + SM3 + SM2 + der(0x04, signature)))
        validate_signed_data_format(two_signers)
        validate_signed_data_format(signed_data(signature))  # Detached content is not needed for format.
        with self.assertRaisesRegex(ValueError, 'invalid SignedData signature'):
            envelope = signed_data(self.signatures['other_key'], attached=MESSAGE)
            validate_signed_data_format(envelope)
            self.verify_attached(envelope)

        attrs = der(0xa0, der(0x30, MESSAGE_DIGEST_OID + der(0x31, der(0x04, bytes(31)))))
        with self.assertRaisesRegex(ValueError, 'messageDigest must contain 32 SM3 octets'):
            validate_signed_data_format(signed_data(signature, signed_attrs=attrs))
        COMPLETED_WITNESSES.add('format_only')

    def test_payment_decision_exhausts_the_declared_domain(self):
        expected = {
            (2, 1, None, SM2, 'direct'),
            (2, 1, MESSAGE, SM2, 'direct'),
        }
        visited, accepted = set(), set()
        self.assertEqual(prod(map(len, AXES)), CASE_COUNT)
        self.assertTrue(all(len(set(axis)) == len(axis) for axis in AXES))
        for case in product(*AXES):
            signer, outer, content, algorithm, payload = case
            with self.subTest(signer=signer, outer=outer,
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
                    self.assertEqual(self.apply_adapter(envelope), self.raw_direct)
                    accepted.add(case)
                else:
                    with self.assertRaises(ValueError):
                        self.apply_adapter(envelope)
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

    def test_embedded_certificate_and_crl_signature_algorithms_match(self):
        cert, crl = self.issue_certificate_and_crl(version_2_crl=True)
        other_algorithm = der(0x30, bytes.fromhex('06082a8648ce3d040302'))
        sm2_algorithm = X509_SM2_OID
        entry_points = ((self.apply_adapter, self.raw_direct), (self.verify_attached, MESSAGE))
        for field, tag, encoded in (('certificates', 0xa0, cert), ('crls', 0xa1, crl)):
            body, extra = remove_sequence(encoded)
            self.assertFalse(extra)
            tbs, outer_fields = remove_sequence(body)
            algorithm, signature_value = remove_sequence(outer_fields)
            self.assertEqual(algorithm, sm2_algorithm)
            variants = (
                ('intact', der(0x30, algorithm)),
                ('different OID', other_algorithm),
                ('different parameters', der(0x30, sm2_algorithm + NULL)),
            )
            for name, outer_algorithm in variants:
                member = der(0x30, der(0x30, tbs) + outer_algorithm + signature_value)
                envelope = signed_data(self.signatures['direct'], attached=MESSAGE, metadata=der(tag, member))
                for entry_point, expected in entry_points:
                    with self.subTest(field=field, variant=name, method=entry_point.__name__):
                        if name == 'intact':
                            self.assertEqual(member, encoded)
                            self.assertEqual(entry_point(envelope), expected)
                        else:
                            reason = f'invalid SignedData {field}: inner and outer signature algorithm identifiers differ'
                            with self.assertRaisesRegex(ValueError, reason):
                                entry_point(envelope)
        COMPLETED_WITNESSES.add('x509_algorithms')

    def test_optional_metadata_exhausts_the_declared_domain(self):
        cert, crl = self.issue_certificate_and_crl()
        unsigned_attribute = der(0x30, bytes.fromhex('06092a864886f70d010902')
                                 + der(0x31, der(0x16, b'Test metadata')))
        states = ('absent', 'empty', 'valid', 'wrong_type')
        axes = ((None, MESSAGE), states, states, states)
        fields = (
            ('certificates', 0xa0, cert),
            ('crls', 0xa1, crl),
            ('unsignedAttrs', 0xa1, unsigned_attribute),
        )
        accepted = set()
        visited = set()
        self.assertTrue(all(len(set(axis)) == len(axis) for axis in axes))
        self.assertEqual(prod(map(len, axes)), 128)
        for case in product(*axes):
            content, *field_states = case
            with self.subTest(attached=content is not None, states=field_states):
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
                envelope = signed_data(self.signatures['direct'], attached=content,
                                       metadata=metadata[0] + metadata[1], unsigned_attrs=metadata[2])
                if invalid:
                    with self.assertRaisesRegex(ValueError, 'invalid SignedData ' + invalid[0]):
                        self.apply_adapter(envelope)
                else:
                    self.assertEqual(self.apply_adapter(envelope), self.raw_direct)
                    accepted.add(case)

        self.assertEqual(len(visited), 128)
        allowed = ('absent', 'empty', 'valid')
        self.assertEqual(accepted, set(product(axes[0], allowed, allowed, ('absent', 'valid'))))
        self.assertEqual(len(accepted), 36)

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
        envelope = signed_data(self.signatures['direct'], metadata=der(0xa1, without_next_update))
        with self.assertRaisesRegex(ValueError, 'invalid SignedData crls: missing CRL nextUpdate'):
            self.apply_adapter(envelope)
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

    def test_open_attribute_values_enforce_der_bit_string_oid_and_octet_string(self):
        oid = der(0x06, bytes.fromhex('2a0304'))
        cases = (
            ('empty BIT STRING', '030100', None),
            ('BIT STRING with no unused bits', '030200ff', None),
            ('BIT STRING with zero padding', '03020780', None),
            ('multi-octet OID subidentifier', '06032a8100', None),
            ('empty OCTET STRING', '0400', None),
            ('opaque OCTET STRING', '04020307', None),
            ('context-specific primitive', '830208ff', None),
            ('missing BIT STRING padding count', '0300', 'BIT STRING'),
            ('BIT STRING padding count above seven', '03020800', 'BIT STRING'),
            ('empty BIT STRING claiming unused bits', '030101', 'BIT STRING'),
            ('nonzero BIT STRING padding', '03020307', 'BIT STRING'),
            ('constructed BIT STRING', '230403020308', 'BIT STRING'),
            ('empty OID value', '0600', 'attribute OID'),
            ('unterminated OID value', '06022a80', 'attribute OID'),
            ('nonminimal OID subidentifier', '06032a8001', 'attribute OID'),
            ('constructed OID', '260306012a', 'attribute OID'),
            ('constructed OCTET STRING', '2403040141', 'OCTET STRING'),
        )
        for name, hex_value, error in cases:
            value = bytes.fromhex(hex_value)
            for nested, node in ((False, value), (True, der(0x30, value))):
                attribute = der(0x30, oid + der(0x31, node))
                unsigned = signed_data(self.signatures['direct'], attached=MESSAGE,
                                       unsigned_attrs=der(0xa1, attribute))
                members = b''.join(sorted((self.attribute, attribute)))
                payload = der(0x31, members)
                signature = self.external_signature(payload)
                self.assertTrue(self.external_verify(signature, payload))
                signed = signed_data(signature, attached=MESSAGE, signed_attrs=der(0xa0, members))
                paths = (
                    (self.apply_adapter, unsigned, self.raw_direct, 'unsignedAttrs'),
                    (self.verify_attached, unsigned, MESSAGE, 'unsignedAttrs'),
                    (self.verify_attached, signed, MESSAGE, 'signedAttrs'),
                )
                for entry_point, envelope, expected, field in paths:
                    with self.subTest(value=name, nested=nested, field=field, method=entry_point.__name__):
                        if error is None:
                            self.assertEqual(entry_point(envelope), expected)
                        else:
                            prefix = 'invalid SignedData unsignedAttrs: ' if field == 'unsignedAttrs' else ''
                            with self.assertRaisesRegex(ValueError, f'^{prefix}invalid DER {error}'):
                                entry_point(envelope)
        COMPLETED_WITNESSES.add('open_value_der')


class SignedDataReview(SignedDataFixtures):
    """Regression witnesses for the findings in the review of 4bcc9d5."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.controls = {}
        cls.rejection_cases = {rule: {} for rule in ('parameters', 'time', 'attributes', 'signature')}
        if not cls.external_verify(cls.signatures['direct'], MESSAGE):
            raise AssertionError('invalid OpenSSL payment signature in review fixtures')
        cls.check_x509_fixtures()
        cls.check_attribute_fixtures()

    @classmethod
    def record_review_case(cls, rule, name, envelope, *, conforming, signed_attributes=False):
        entry_points = [(cls.verify_attached, MESSAGE)]
        if not signed_attributes:
            entry_points.append((cls.apply_adapter, cls.raw_direct))
        outcomes = cls.controls if conforming else cls.rejection_cases[rule]
        for entry_point, expected in entry_points:
            label = (rule, name, entry_point.__name__)
            if label in outcomes:
                raise AssertionError(f'duplicate review fixture {label}')
            try:
                result = entry_point(envelope)
            except ValueError:
                outcomes[label] = False
            else:
                if result != expected:
                    raise AssertionError(f'{label} returned an unexpected payload or signature')
                outcomes[label] = True

    @classmethod
    def check_x509_fixtures(cls):
        cert, crl = cls.issue_certificate_and_crl(version_2_crl=True)
        certificate = load_der_x509_certificate(cert)
        revocation_list = load_der_x509_crl(crl)
        metadata = (
            ('certificate', 0xa0, cert, ('notBefore', 'notAfter'),
             (certificate.not_valid_before_utc, certificate.not_valid_after_utc)),
            ('CRL', 0xa1, crl, ('thisUpdate', 'nextUpdate'),
             (revocation_list.last_update_utc, revocation_list.next_update_utc)),
        )
        for kind, tag, encoded, names, source_dates in metadata:
            body, algorithm = x509_signed_parts(encoded)
            if algorithm != X509_SM2_OID:
                raise AssertionError('OpenSSL control must omit SM2 parameters')
            cls.record_review_metadata('parameters', kind, tag, encoded, conforming=True)
            with_null = algorithm + NULL
            updated = cls.replace_fixture_field(body, der(0x30, algorithm), der(0x30, with_null))
            cls.record_review_metadata('parameters', kind, tag, cls.sign_review_metadata(updated, with_null),
                                       conforming=False)
            for signature_type, bits, raw in (
                ('wrong signature tag', 0, der(0x04, b'test-only')),
                ('zero signature scalar', 0, bytes.fromhex('3006020100020101')),
                ('unaligned signature', 1, bytes.fromhex('3006020101020102')),
            ):
                member = der(0x30, der(0x30, body) + der(0x30, algorithm) + der(0x03, bytes((bits,)) + raw))
                cls.record_review_metadata('signature', f'{kind} {signature_type}', tag, member,
                                           conforming=False)

            def encode_dates(values):
                data = b''.join(values)
                return der(0x30, data) if kind == 'certificate' else data

            source_times = []
            for date in source_dates:
                if date.year <= 2049:
                    source_times.append(der(0x17, date.strftime('%y%m%d%H%M%SZ').encode()))
                else:
                    source_times.append(der(0x18, date.strftime('%Y%m%d%H%M%SZ').encode()))
            original_dates = encode_dates(source_times)
            dates_2049 = (b'491231000000Z', b'491231010000Z')
            utc_times = [der(0x17, date) for date in dates_2049]
            generalized_times = [der(0x18, date) for date in (b'20500101000000Z', b'20500101010000Z')]
            for year, times in ((2049, utc_times), (2050, generalized_times)):
                updated = cls.replace_fixture_field(body, original_dates, encode_dates(times))
                cls.record_review_metadata('time', f'{kind} {year}', tag,
                                           cls.sign_review_metadata(updated, algorithm), conforming=True)
            for index, field in enumerate(names):
                times = utc_times.copy()
                times[index] = der(0x18, b'20' + dates_2049[index])
                updated = cls.replace_fixture_field(body, original_dates, encode_dates(times))
                cls.record_review_metadata('time', f'{kind} {field} in 2049', tag,
                                           cls.sign_review_metadata(updated, algorithm), conforming=False)

    @staticmethod
    def replace_fixture_field(body, original, replacement):
        if body.count(original) != 1:
            raise AssertionError('expected one DER field to replace in the OpenSSL fixture')
        return body.replace(original, replacement, 1)

    @classmethod
    def sign_review_metadata(cls, body, algorithm, *, key='signer', user_id=USER_ID):
        tbs = der(0x30, body)
        signature = cls.external_signature(tbs, key=key, user_id=user_id)
        if not cls.external_verify(signature, tbs, key=key, user_id=user_id):
            raise AssertionError('invalid OpenSSL signature over review metadata')
        return der(0x30, tbs + der(0x30, algorithm) + der(0x03, b'\x00' + signature))

    @classmethod
    def record_review_metadata(cls, rule, name, tag, encoded, *, conforming):
        envelope = signed_data(cls.signatures['direct'], attached=MESSAGE, metadata=der(tag, encoded))
        cls.record_review_case(rule, name, envelope, conforming=conforming)

    @classmethod
    def check_attribute_fixtures(cls):
        oid = der(0x06, bytes.fromhex('2a0304'))
        cases = (
            ('SEQUENCE form', '3000', '1000'),
            ('SET form', '3100', '1100'),
            ('UTF8String form', '0c0141', '2c030c0141'),
            ('UTF8String repertoire', '0c03e4b8ad', '0c02c080'),
            ('PrintableString form', '130141', '3303130141'),
            ('ENUMERATED length', '0a0101', '0a00'),
            ('ENUMERATED minimal integer', '0a020080', '0a020001'),
            ('ENUMERATED form', '0a0101', '2a030a0101'),
            ('RELATIVE-OID subidentifier', '0d028100', '0d028001'),
            ('RELATIVE-OID form', '0d0101', '2d030d0101'),
            ('NumericString repertoire', '1203312032', '1203412032'),
            ('PrintableString repertoire', '130141', '130140'),
            ('IA5String repertoire', '16017f', '160180'),
            ('VisibleString repertoire', '1a017e', '1a011f'),
            ('UTCTime seconds', der(0x17, b'491231235959Z').hex(), der(0x17, b'4912312359Z').hex()),
            ('GeneralizedTime fraction', der(0x18, b'20500101000000.5Z').hex(),
             der(0x18, b'20500101000000.50Z').hex()),
        )
        for name, valid, invalid in cases:
            for conforming, value in ((True, valid), (False, invalid)):
                value = bytes.fromhex(value)
                for location, node in (('direct', value), ('nested', der(0x30, value))):
                    attribute = der(0x30, oid + der(0x31, node))
                    unsigned = signed_data(cls.signatures['direct'], attached=MESSAGE,
                                           unsigned_attrs=der(0xa1, attribute))
                    cls.record_review_case('attributes', f'{name} {location} unsignedAttrs',
                                           unsigned, conforming=conforming)
                    members = b''.join(sorted((attribute, cls.attribute)))
                    payload = der(0x31, members)
                    signature = cls.external_signature(payload)
                    if not cls.external_verify(signature, payload):
                        raise AssertionError('invalid OpenSSL signedAttrs signature in review fixtures')
                    signed = signed_data(signature, attached=MESSAGE, signed_attrs=der(0xa0, members))
                    cls.record_review_case('attributes', f'{name} {location} signedAttrs',
                                           signed, conforming=conforming, signed_attributes=True)

    def test_review_controls_and_case_counts(self):
        self.assertEqual(len(self.controls), 108)
        self.assertEqual({rule: len(cases) for rule, cases in self.rejection_cases.items()},
                         {'parameters': 4, 'time': 8, 'attributes': 96, 'signature': 12})
        self.assertEqual([case for case, accepted in self.controls.items() if not accepted], [])

    def test_rejects_null_sm2_parameters_in_certificates_and_crls(self):
        self.assertEqual([case for case, accepted in self.rejection_cases['parameters'].items() if accepted], [])
        COMPLETED_WITNESSES.add('x509_parameters')

    def test_rejects_pre_2050_generalized_time_in_certificates_and_crls(self):
        self.assertEqual([case for case, accepted in self.rejection_cases['time'].items() if accepted], [])
        COMPLETED_WITNESSES.add('x509_time')

    def test_rejects_non_der_sequence_set_string_and_enumerated_attribute_values(self):
        self.assertEqual([case for case, accepted in self.rejection_cases['attributes'].items() if accepted], [])
        COMPLETED_WITNESSES.add('open_value_forms')

    def test_rejects_invalid_sm2_signature_values_in_certificates_and_crls(self):
        self.assertEqual([case for case, accepted in self.rejection_cases['signature'].items() if accepted], [])
        COMPLETED_WITNESSES.add('x509_signature')

    def test_x509_extension_values_and_version_dependencies(self):
        certificate, crl = self.issue_certificate_and_crl(version_2_crl=True)
        cert_body, cert_algorithm = x509_signed_parts(certificate)
        crl_body, crl_algorithm = x509_signed_parts(crl)
        cert_fields = tuple(encoded_fields(cert_body))
        crl_fields = tuple(encoded_fields(crl_body))
        self.assertEqual(cert_fields[0], bytes.fromhex('a003020102'))
        self.assertEqual(crl_fields[0], b'\x02\x01\x01')
        cert_core = b''.join(cert_fields[1:7])
        crl_core = b''.join(crl_fields[1:5])
        revoked_entry = der(0x02, b'\x02') + der(0x17, b'251231000000Z')

        def certificate_body(extensions, version=b'\xa0\x03\x02\x01\x02'):
            return version + cert_core + der(0xa3, extensions)

        def crl_body_with_extensions(extensions, version=b'\x02\x01\x01'):
            return version + crl_core + der(0xa0, extensions)

        def crl_entry_body(extensions, version=b'\x02\x01\x01'):
            return version + crl_core + der(0x30, der(0x30, revoked_entry + extensions))

        def extension(oid, value, critical=b''):
            return der(0x30, oid + critical + der(0x04, value))

        private_oid = bytes.fromhex('06032a0306')
        private_extension = extension(private_oid, NULL)
        contexts = (
            ('certificate', 0xa0, cert_algorithm, certificate_body,
             bytes.fromhex('0603551d0e'), der(0x04, b'key identifier')),
            ('CRL', 0xa1, crl_algorithm, crl_body_with_extensions,
             bytes.fromhex('0603551d14'), der(0x02, b'\x01')),
            ('CRL entry', 0xa1, crl_algorithm, crl_entry_body,
             bytes.fromhex('0603551d15'), der(0x0a, b'\x01')),
        )
        for kind, tag, algorithm, build, known_oid, known_value in contexts:
            cases = (
                ('private extension', private_extension, None),
                ('known extension', extension(known_oid, known_value), None),
                ('empty extension sequence', b'', 'empty X.509 Extensions'),
                ('duplicate extension OID', private_extension * 2, 'duplicate X.509 extension OID'),
                ('explicit default FALSE', extension(private_oid, NULL, b'\x01\x01\x00'),
                 'critical must be TRUE or omitted'),
                ('extra encapsulated data', extension(private_oid, NULL * 2), 'trailing or unsupported'),
                ('invalid known extension type', extension(known_oid, NULL), 'invalid SignedData'),
            )
            for name, extensions, error in cases:
                body = build(der(0x30, extensions))
                with self.subTest(kind=kind, issue=name):
                    self.check_extension_envelope(tag, body, algorithm, error)
            with self.subTest(kind=kind, issue='extensions in v1'):
                body = build(der(0x30, private_extension), version=b'')
                self.check_extension_envelope(tag, body, algorithm, 'extensions require')

        self.check_extension_envelope(0xa0, cert_core, cert_algorithm)
        self.check_extension_envelope(0xa1, crl_core, crl_algorithm)
        v2_certificate = b'\xa0\x03\x02\x01\x01' + cert_core
        issuer_id = der(0x81, b'\x00\xff')
        subject_id = der(0x82, b'\x01\x80')
        self.check_extension_envelope(0xa0, v2_certificate + issuer_id + subject_id, cert_algorithm)
        self.check_extension_envelope(0xa0, v2_certificate + der(0xa3, der(0x30, private_extension)),
                                      cert_algorithm, 'certificate extensions require v3')
        self.check_extension_envelope(0xa0, b'\xa0\x03\x02\x01\x00' + cert_core,
                                      cert_algorithm, 'omitted v1 default')
        self.check_extension_envelope(0xa0, cert_core + der(0x81, b'\x00\xff'),
                                      cert_algorithm, 'unique identifiers require v2 or v3')
        self.check_extension_envelope(0xa1, b'\x02\x01\x00' + crl_core, crl_algorithm, 'omitted v1 version')
        COMPLETED_WITNESSES.add('x509_extensions')

    def test_schema_aware_der_for_signed_and_unsigned_attributes(self):
        class IntegerSet(SetOf):
            _child_spec = Integer

        oid = der(0x06, bytes.fromhex('2a0304'))
        schemas = {'1.2.3.4': IntegerSet}
        first, second = der(2, b'\x01'), der(2, b'\x02')
        cases = (
            ('canonical SET OF', der(0x31, first + second), True),
            ('wrong SET OF order', der(0x31, second + first), False),
            ('wrong ASN.1 type', der(0x04, b'test-only'), False),
        )
        for label, value, accepted in cases:
            attribute = der(0x30, oid + der(0x31, value))
            members = b''.join(sorted((self.attribute, attribute)))
            payload = der(0x31, members)
            signature = self.external_signature(payload)
            self.assertTrue(self.external_verify(signature, payload))
            envelopes = (
                ('signedAttrs', signed_data(signature, attached=MESSAGE, signed_attrs=der(0xa0, members))),
                ('unsignedAttrs', signed_data(self.signatures['direct'], attached=MESSAGE,
                                             unsigned_attrs=der(0xa1, attribute))),
            )
            for field, envelope in envelopes:
                with self.subTest(field=field, case=label):
                    self.assertEqual(self.verify_attached(envelope), MESSAGE)
                    with self.assertRaisesRegex(MissingAttributeSchema, r'1\.2\.3\.4'):
                        verify_signed_data(envelope, self.trusted_signers, attribute_schemas={})
                    if accepted:
                        self.assertEqual(verify_signed_data(envelope, self.trusted_signers,
                                                            attribute_schemas=schemas), MESSAGE)
                    else:
                        with self.assertRaisesRegex(ValueError, r'invalid DER value for SignedData attribute 1\.2\.3\.4'):
                            verify_signed_data(envelope, self.trusted_signers, attribute_schemas=schemas)
        COMPLETED_WITNESSES.add('attribute_schemas')

    def test_chapter_8_certificate_profile_constraints(self):
        certificate, _ = self.issue_certificate_and_crl()
        cert_body, algorithm = x509_signed_parts(certificate)
        fields = tuple(encoded_fields(cert_body))
        certificate_prefix = b''.join(fields[:5])
        subject, spki = fields[5:7]

        def extension(number, value, *, critical=False):
            critical_field = b'\x01\x01\xff' if critical else b''
            return der(0x30, der(0x06, bytes((0x55, 0x1d, number))) + critical_field + der(0x04, value))

        ski = extension(14, der(0x04, b'test subject key identifier'))
        critical_ski = extension(14, der(0x04, b'test subject key identifier'), critical=True)
        aki_value = der(0x30, der(0x80, b'test authority key identifier'))
        aki = extension(35, aki_value)
        critical_aki = extension(35, aki_value, critical=True)
        ca_value = der(0x30, b'\x01\x01\xff')
        basic = extension(19, ca_value, critical=True)
        noncritical_basic = extension(19, ca_value)
        explicit_non_ca = extension(19, der(0x30, b'\x01\x01\x00'))
        key_cert_sign = extension(15, der(0x03, b'\x02\x04'), critical=True)
        san_value = der(0x30, der(0x82, b'subject.example'))
        critical_san = extension(17, san_value, critical=True)
        noncritical_san = extension(17, san_value)
        empty_san = extension(17, der(0x30, b''), critical=True)
        subtree = der(0x30, der(0x82, b'subject.example'))
        constraints = extension(30, der(0x30, der(0xa0, subtree)), critical=True)
        any_policy = bytes.fromhex('0604551d2000')
        left_policy = bytes.fromhex('06032a0304')
        right_policy = bytes.fromhex('06032a0305')

        def mapping(left, right):
            return extension(33, der(0x30, der(0x30, left + right)))

        ca = basic + ski + key_cert_sign
        cases = (
            ('end entity', subject, aki, None),
            ('empty subject with critical SAN', b'\x30\x00', critical_san, None),
            ('CA with constraints and mapping', subject, ca + constraints + mapping(left_policy, right_policy), None),
            ('critical AKI', subject, critical_aki, 'authorityKeyIdentifier must be noncritical'),
            ('critical SKI', subject, critical_ski, 'subjectKeyIdentifier must be noncritical'),
            ('empty subject without SAN', b'\x30\x00', ski, 'empty certificate subject'),
            ('empty subject with noncritical SAN', b'\x30\x00', noncritical_san, 'requires critical subjectAltName'),
            ('empty SAN', subject, empty_san, 'subjectAltName must contain at least one name'),
            ('empty CA subject', b'\x30\x00', ca + critical_san, 'CA certificate requires a nonempty subject'),
            ('noncritical CA constraints', subject, noncritical_basic + ski + key_cert_sign,
             'CA basicConstraints must be critical'),
            ('CA without SKI', subject, basic + key_cert_sign, 'requires subjectKeyIdentifier'),
            ('CA without keyCertSign', subject, basic + ski, 'requires keyCertSign'),
            ('keyCertSign without CA', subject, ski + key_cert_sign, 'keyCertSign requires basicConstraints'),
            ('explicit cA default', subject, explicit_non_ca, 'cA FALSE must be omitted'),
            ('name constraints on end entity', subject, ski + constraints, 'nameConstraints requires a CA certificate'),
            ('anyPolicy as issuer policy', subject, ca + mapping(any_policy, right_policy), 'must not contain anyPolicy'),
            ('anyPolicy as subject policy', subject, ca + mapping(left_policy, any_policy), 'must not contain anyPolicy'),
        )
        for label, name, extensions, error in cases:
            body = certificate_prefix + name + spki + der(0xa3, der(0x30, extensions))
            cert = self.sign_review_metadata(body, algorithm)
            envelope = signed_data(self.signatures['direct'], attached=MESSAGE, include_signer=False,
                                   digest_algorithms=b'', metadata=der(0xa0, cert))
            with self.subTest(case=label):
                if error is None:
                    validate_signed_data_format(envelope)
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        validate_signed_data_format(envelope)
        COMPLETED_WITNESSES.add('certificate_profile')

    def check_certificate_extensions(self, cases, *, schemas=None):
        certificate, _ = self.issue_certificate_and_crl(version_2_crl=True)
        body, algorithm = x509_signed_parts(certificate)
        prefix = b''.join(tuple(encoded_fields(body))[:7])
        for label, extensions, error in cases:
            member = self.sign_review_metadata(prefix + der(0xa3, der(0x30, extensions)), algorithm)
            envelope = signed_data(self.signatures['direct'], attached=MESSAGE, include_signer=False,
                                   digest_algorithms=b'', metadata=der(0xa0, member))
            with self.subTest(case=label):
                if error is None:
                    validate_signed_data_format(envelope, extension_schemas=schemas)
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        validate_signed_data_format(envelope, extension_schemas=schemas)

    def test_name_and_policy_constraints_on_ca_certificates(self):
        ca = (x509_extension('2.5.29.19', der(0x30, der(0x01, b'\xff')), critical=True)
              + x509_extension('2.5.29.14', der(0x04, b'test key identifier'))
              + x509_extension('2.5.29.15', der(0x03, b'\x02\x04'), critical=True))
        dns = der(0x82, b'subject.example')
        subtree = der(0x30, dns)

        def names(*fields):
            return x509_extension('2.5.29.30', der(0x30, b''.join(fields)))

        def policies(*fields):
            return x509_extension('2.5.29.36', der(0x30, b''.join(fields)))

        mapping = x509_extension('2.5.29.33', der(0x30, der(0x30, bytes.fromhex('06032a030406032a0305'))))
        misplaced = (('nameConstraints', names(der(0xa0, subtree))), ('policyMappings', mapping),
                     ('policyConstraints', policies(der(0x80, b'\x00'))))
        cases = [(name + ' on end entity', extension, name + ' requires a CA certificate')
                 for name, extension in misplaced]
        for tag in (0xa0, 0xa1):
            cases.append((f'present subtree {tag:#x}', ca + names(der(tag, subtree)), None))
            cases.append((f'empty subtree {tag:#x}', ca + names(der(tag, b'')), 'at least one subtree'))
            for field, value in ((0x80, b'\x00'), (0x80, b'\x01'), (0x81, b'\x00'), (0x81, b'\x01')):
                constraint = names(der(tag, der(0x30, dns + der(field, value))))
                cases.append((f'subtree distance {tag:#x} {field:#x}={value.hex()}', ca + constraint,
                              'minimum and maximum must be omitted'))
        cases.append(('both name scopes', ca + names(der(0xa0, subtree), der(0xa1, subtree)), None))
        for tag in (0x80, 0x81):
            for value, error in ((b'\x00', None), (b'\x7f', None), (b'\x00\x80', None),
                                 (b'\xff', 'nonnegative DER INTEGER'), (b'\x00\x7f', 'nonnegative DER INTEGER')):
                cases.append((f'SkipCerts {tag:#x}={value.hex()}', ca + policies(der(tag, value)), error))
        cases.append(('both policy constraints', ca + policies(der(0x80, b'\x00'), der(0x81, b'\x01')), None))
        self.assertEqual(len(cases), 27)
        self.check_certificate_extensions(cases)
        COMPLETED_WITNESSES.add('certificate_constraints')

    def test_certificate_name_distribution_and_access_extension_shapes(self):
        cases = []
        dns = der(0x82, b'issuer.example')
        uri = der(0x86, b'https://issuer.example/x509')
        point = der(0x30, der(0xa0, der(0xa0, uri)))
        access = der(0x30, ObjectIdentifier('1.3.6.1.5.5.7.48.2').dump() + uri)
        for oid, name, member, empty_error in (
            ('2.5.29.18', 'issuerAltName', dns, 'entry'),
            ('2.5.29.31', 'cRLDistributionPoints', point, 'entry'),
            ('2.5.29.46', 'freshestCRL', point, 'entry'),
            ('1.3.6.1.5.5.7.1.1', 'authorityInfoAccess', access, 'access description'),
            ('1.3.6.1.5.5.7.1.11', 'subjectInformationAccess', access, 'access description'),
        ):
            cases.append((name + ' present', x509_extension(oid, der(0x30, member)), None))
            cases.append((name + ' empty', x509_extension(oid, der(0x30, b'')),
                          f'{name} must contain at least one {empty_error}'))
            error = f'{name} must be noncritical' if empty_error == 'access description' else None
            cases.append((name + ' critical', x509_extension(oid, der(0x30, member), critical=True), error))
        for name, member in (('DNS', der(0x82, b'')), ('email', der(0x81, b'')), ('URI', der(0x86, b'')),
                             ('directory', der(0xa4, der(0x30, b'')))):
            san = x509_extension('2.5.29.17', der(0x30, dns + member))
            cases.append(('SAN with an empty ' + name, san, 'subjectAltName must not contain an empty name'))
        self.assertEqual(len(cases), 19)
        self.check_certificate_extensions(cases)
        COMPLETED_WITNESSES.add('certificate_extension_shapes')

    def test_national_certificate_identification_number_types(self):
        cases = []
        for number in range(2, 6):
            oid = f'1.2.156.10260.4.1.{number}'
            for case, value, critical, error in (
                ('PrintableString', der(0x13, b'Fixture-123'), False, None),
                ('critical', der(0x13, b'Fixture-123'), True, 'identification number extensions must be noncritical'),
                ('wrong string type', der(0x0c, b'Fixture-123'), False, 'identification number extensions require PrintableString'),
                ('invalid character', der(0x13, b'Fixture_123'), False, 'invalid DER PrintableString'),
            ):
                cases.append((f'{oid} {case}', x509_extension(oid, value, critical=critical), error))
        self.assertEqual(len(cases), 16)
        self.check_certificate_extensions(cases, schemas={})
        COMPLETED_WITNESSES.add('certificate_identification_numbers')

    def test_chapter_8_crl_profile_constraints(self):
        _, crl = self.issue_certificate_and_crl(version_2_crl=True)
        body, algorithm = x509_signed_parts(crl)
        fields = tuple(encoded_fields(body))
        self.assertEqual(fields[0], b'\x02\x01\x01')
        prefix = b''.join(fields[:5])

        def extension(number, value, *, critical=False):
            critical_field = b'\x01\x01\xff' if critical else b''
            return der(0x30, der(0x06, bytes((0x55, 0x1d, number))) + critical_field + der(0x04, value))

        number = extension(20, der(0x02, b'\x06'))
        delta = extension(27, der(0x02, b'\x05'), critical=True)
        distribution = der(0x30, der(0x81, b'\xff'))
        cases = (
            ('complete CRL', number + extension(28, distribution, critical=True), None),
            ('delta CRL', number + delta, None),
            ('delta without own number', delta, 'delta CRL requires cRLNumber'),
            ('delta equal to its base', extension(20, der(0x02, b'\x05')) + delta,
             'delta CRL number must be greater than its BaseCRLNumber'),
            ('delta lower than its base', extension(20, der(0x02, b'\x04')) + delta,
             'delta CRL number must be greater than its BaseCRLNumber'),
            ('twenty-octet CRL number', extension(20, der(0x02, b'\x7f' + b'\xff' * 19)), None),
            ('critical AKI', extension(35, der(0x30, der(0x80, b'test key identifier')), critical=True),
             'authorityKeyIdentifier must be noncritical'),
            ('empty issuer alternative name', extension(18, der(0x30, b'')), 'issuerAltName must contain'),
            ('critical CRL number', extension(20, der(0x02, b'\x01'), critical=True), 'cRLNumber must be noncritical'),
            ('oversized CRL number', extension(20, der(0x02, b'\x00\x80' + bytes(19))),
             'cRLNumber requires a nonnegative DER INTEGER of at most 20 octets'),
            ('noncritical delta', number + extension(27, der(0x02, b'\x05')), 'deltaCRLIndicator must be critical'),
            ('oversized delta base', number + extension(27, der(0x02, b'\x01' + bytes(20)), critical=True),
             'deltaCRLIndicator requires a nonnegative DER INTEGER of at most 20 octets'),
            ('noncritical distribution point', number + extension(28, distribution),
             'issuingDistributionPoint must be critical'),
        )
        for label, extensions, error in cases:
            member = self.sign_review_metadata(prefix + der(0xa0, der(0x30, extensions)), algorithm)
            envelope = signed_data(self.signatures['direct'], attached=MESSAGE, include_signer=False,
                                   digest_algorithms=b'', metadata=der(0xa1, member))
            with self.subTest(case=label):
                if error is None:
                    validate_signed_data_format(envelope)
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        validate_signed_data_format(envelope)
        COMPLETED_WITNESSES.add('crl_profile')

    def crl_revision_factory(self):
        _, crl = self.issue_certificate_and_crl(version_2_crl=True)
        body, algorithm = x509_signed_parts(crl)
        version, signature, _, _, next_update, *_ = encoded_fields(body)

        def issue(time, number, *, base=None, common_name=b'Review issuer', name_tag=0x0c,
                  scope=None, domain=None, repeated_name=None, entries=(), authority_key=None,
                  extra_extensions=b'', expiry=None, signing_key='signer', user_id=USER_ID):
            def rdn_attribute(oid, tag, value):
                return der(0x30, ObjectIdentifier(oid).dump() + der(tag, value))

            attributes = [rdn_attribute('2.5.4.3', name_tag, common_name)]
            if repeated_name is not None:
                attributes.append(rdn_attribute('2.5.4.3', name_tag, repeated_name))
            issuer = der(0x31, b''.join(sorted(attributes)))
            if domain is not None:
                issuer += der(0x31, rdn_attribute('0.9.2342.19200300.100.1.25', 0x16, domain))
            revision = b'' if number is None else x509_extension('2.5.29.20', Integer(number).dump())
            if base is not None:
                revision += x509_extension('2.5.29.27', Integer(base).dump(), critical=True)
            if scope is not None:
                revision += x509_extension('2.5.29.28', der(0x30, der(scope, b'\xff')), critical=True)
            if authority_key is not None:
                revision += x509_extension('2.5.29.35', der(0x30, der(0x80, authority_key)))
            revision += extra_extensions
            expires = next_update if expiry is None else der(0x17, expiry)
            fields = version + signature + der(0x30, issuer) + der(0x17, time) + expires
            if entries:
                fields += der(0x30, b''.join(entries))
            if revision:
                fields += der(0xa0, der(0x30, revision))
            return self.sign_review_metadata(fields, algorithm, key=signing_key, user_id=user_id)

        return issue

    def test_crl_series_numbering_exhausts_the_declared_comparison_domain(self):
        issue = self.crl_revision_factory()
        times = (b'250101000000Z', b'250102000000Z', b'250103000000Z')
        # Each pair independently varies role, issue-time order and number order.
        revisions = {(time, number, base): issue(time, number, base=base)
                     for time, number, base in product(times, (1, 2, 3), (None, 0))}
        rows = tuple(product((None, 0), (None, 0), times, (1, 2, 3)))
        self.assertEqual(len(rows), 36)
        for first_role, second_role, second_time, second_number in rows:
            first = revisions[times[1], 2, first_role]
            second = revisions[second_time, second_number, second_role]
            error = None
            if second_time == times[1]:
                if first_role != second_role and second_number != 2:
                    error = 'issued at the same time must have the same number'
            elif (second_time > times[1] and second_number <= 2
                  or second_time < times[1] and second_number >= 2):
                error = 'CRL numbers must increase with thisUpdate'
            for first_input, second_input in ((first, second), (second, first)):
                with self.subTest(first_role=first_role, second_role=second_role,
                                  second_time=second_time, second_number=second_number, reverse=first_input != first):
                    if error is None:
                        validate_crl_series(iter((first_input, second_input)))
                    else:
                        with self.assertRaisesRegex(ValueError, error):
                            validate_crl_series(iter((first_input, second_input)))

        release = issue(times[2], 3, base=0)
        earlier_1 = issue(times[0], 1)
        earlier_2 = issue(times[1], 2)
        validate_crl_series((release, earlier_1, earlier_2))
        # The first and last alone agree. A middle revision reusing the first
        # number must still be rejected when the supplied series is unsorted.
        with self.assertRaisesRegex(ValueError, 'CRL numbers must increase'):
            validate_crl_series((release, earlier_1, issue(times[1], 1)))
        with self.assertRaisesRegex(ValueError, 'CRL revision requires cRLNumber'):
            validate_crl_series((issue(times[0], None),))
        with self.assertRaisesRegex(ValueError, 'expected at least one CRL revision'):
            validate_crl_series(())
        COMPLETED_WITNESSES.add('crl_series')

    def test_crl_pair_requires_compatible_roles_issuer_scope_numbers_and_times(self):
        issue = self.crl_revision_factory()
        early, current, late = (b'250101000000Z', b'250102000000Z', b'250103000000Z')
        delta = issue(current, 4, base=2)
        rows = tuple(product((1, 2, 3, 4, 5), (early, current, late)))
        self.assertEqual(len(rows), 15)
        for number, time in rows:
            complete = issue(time, number)
            with self.subTest(number=number, time=time):
                if number < 2 or number >= 4:
                    with self.assertRaisesRegex(ValueError, 'complete CRL number must be at least BaseCRLNumber'):
                        validate_crl_pair(complete, delta)
                elif time == current:
                    with self.assertRaisesRegex(ValueError, 'issued at the same time must have the same number'):
                        validate_crl_pair(complete, delta)
                elif time == late:
                    with self.assertRaisesRegex(ValueError, 'CRL numbers must increase'):
                        validate_crl_pair(complete, delta)
                else:
                    validate_crl_pair(complete, delta)

        complete = issue(early, 2)
        scoped_base = issue(early, 2, scope=0x81)
        scoped_delta = issue(current, 4, base=2, scope=0x81)
        validate_crl_pair(scoped_base, scoped_delta)
        validate_crl_pair(issue(early, 0), issue(current, 1, base=0))
        validate_crl_pair(issue(early, 2, common_name=b'  ReViEw   ISSUER ', name_tag=0x13, domain=b'EXAMPLE'),
                          issue(current, 4, base=2, domain=b'example'))
        differing = (
            ('delta in first position', issue(early, 2, base=1), delta, 'complete CRL followed by a delta CRL'),
            ('complete in second position', complete, issue(current, 4), 'complete CRL followed by a delta CRL'),
            ('different DN', issue(early, 2, common_name=b'Other issuer'), delta, 'same issuer name'),
            ('repeated DN attribute', issue(early, 2, repeated_name=b'Another name'), delta, 'same issuer name'),
            ('IDP only on complete', scoped_base, delta, 'same issuing distribution point scope'),
            ('IDP only on delta', complete, scoped_delta, 'same issuing distribution point scope'),
            ('different IDPs', scoped_base, issue(current, 4, base=2, scope=0x82), 'same issuing distribution point scope'),
        )
        for label, candidate, update, error in differing:
            with self.subTest(case=label):
                with self.assertRaisesRegex(ValueError, error):
                    validate_crl_pair(candidate, update)
        COMPLETED_WITNESSES.add('crl_pair')

    def test_crl_revocation_merge_exhausts_the_declared_state_domain(self):
        issue = self.crl_revision_factory()
        issuer = Name([NameAttribute(NameOID.COMMON_NAME, 'Review issuer')])
        early = b'250101000000Z'
        late = b'250102000000Z'
        expiry = b'250202000000Z'
        invalidity = b'20241230000000Z'
        base_reasons = {'absent': None, 'unspecified': None, 'hold': 6, 'key compromise': 1}
        delta_reasons = {**base_reasons, 'remove': 8}
        expected_reasons = {'unspecified': ReasonFlags.unspecified, 'hold': ReasonFlags.certificate_hold,
                            'key compromise': ReasonFlags.key_compromise}
        cases = tuple(product(base_reasons, delta_reasons))
        self.assertEqual(len(cases), 20)

        def entries(status, reason, date, *, invalidity_date=None):
            if status == 'absent':
                return ()
            return (review_revoked_entry(1, date, reason=reason, invalidity=invalidity_date),)

        for base_status, delta_status in cases:
            complete = issue(early, 1, expiry=b'250201000000Z', entries=entries(base_status, base_reasons[base_status], early))
            updated = entries(delta_status, delta_reasons[delta_status], late, invalidity_date=invalidity)
            delta = issue(late, 2, base=1, expiry=expiry, entries=updated)
            with self.subTest(base=base_status, delta=delta_status):
                snapshot = merge_crl_revocations(complete, delta)
                self.assertEqual(snapshot.number, 2)
                self.assertEqual(snapshot.this_update, datetime(2025, 1, 2, tzinfo=timezone.utc))
                self.assertEqual(snapshot.next_update, datetime(2025, 2, 2, tzinfo=timezone.utc))
                self.assertIsNone(snapshot.issuing_distribution_point)
                selected = snapshot.revocation_for(issuer, 1)
                expected = base_status if delta_status == 'absent' else delta_status
                if expected in ('absent', 'remove'):
                    self.assertIsNone(selected)
                else:
                    self.assertEqual(selected.reason, expected_reasons[expected])
                    from_delta = delta_status != 'absent'
                    day = 2 if from_delta else 1
                    self.assertEqual(selected.revocation_date, datetime(2025, 1, day, tzinfo=timezone.utc))
                    self.assertEqual(selected.invalidity_date, datetime(2024, 12, 30, tzinfo=timezone.utc) if from_delta else None)
        COMPLETED_WITNESSES.add('crl_revocation_merge')

    def test_indirect_crl_state_separates_issuers_and_inherits_names_per_list(self):
        issue = self.crl_revision_factory()
        early, late = b'250101000000Z', b'250102000000Z'
        authority, issuer_a, issuer_b = (Name([NameAttribute(NameOID.COMMON_NAME, name)])
                                         for name in ('Review issuer', 'Issuer A', 'Issuer B'))
        name_a = der(0xa4, der(0x30, common_name_rdn(b'Issuer A')))
        equivalent_a = der(0xa4, der(0x30, common_name_rdn(b'  ISSUER  A ')))
        name_b = der(0xa4, der(0x30, common_name_rdn(b'Issuer B')))
        own_name = der(0xa4, der(0x30, common_name_rdn(b'Review issuer')))
        complete = issue(early, 1, scope=0x84, entries=(
            review_revoked_entry(1, early, reason=1),
            review_revoked_entry(1, early, reason=6, issuers=(name_a,)),
            review_revoked_entry(2, early, reason=6),
            review_revoked_entry(1, early, reason=6, issuers=(name_b,)),
            review_revoked_entry(3, early, reason=6),
        ))
        delta = issue(late, 2, scope=0x84, base=1, entries=(
            review_revoked_entry(2, late, reason=4),
            review_revoked_entry(1, late, reason=8, issuers=(equivalent_a,)),
            review_revoked_entry(2, late, reason=1),
            review_revoked_entry(4, late, reason=5, issuers=(own_name,)),
        ))
        snapshot = merge_crl_revocations(complete, delta)
        self.assertEqual(snapshot.issuing_distribution_point, der(0x30, der(0x84, b'\xff')))
        for issuer, serial, reason in (
            (authority, 1, ReasonFlags.key_compromise), (authority, 2, ReasonFlags.superseded),
            (authority, 4, ReasonFlags.cessation_of_operation), (issuer_a, 1, None),
            (issuer_a, 2, ReasonFlags.key_compromise), (issuer_b, 1, ReasonFlags.certificate_hold),
            (issuer_b, 2, None), (issuer_b, 3, ReasonFlags.certificate_hold),
        ):
            with self.subTest(issuer=issuer, serial=serial):
                entry = snapshot.revocation_for(issuer, serial)
                self.assertEqual(entry.reason if entry is not None else None, reason)
        COMPLETED_WITNESSES.add('crl_indirect_issuer')

    def test_crl_merge_rejects_ambiguous_unsupported_and_duplicate_entries(self):
        issue = self.crl_revision_factory()
        early, late = b'250101000000Z', b'250102000000Z'
        name_a = der(0xa4, der(0x30, common_name_rdn(b'Issuer A')))
        name_b = der(0xa4, der(0x30, common_name_rdn(b'Issuer B')))
        complete = issue(early, 1)
        delta = issue(late, 2, base=1)
        indirect_complete = issue(early, 1, scope=0x84)
        indirect_delta = issue(late, 2, base=1, scope=0x84)
        duplicate = review_revoked_entry(1, early, reason=6)
        unknown_critical = x509_extension('1.2.3.4', Integer(2).dump(), critical=True)
        unknown_noncritical = x509_extension('1.2.3.4', Integer(2).dump())
        self.assertIsNone(merge_crl_revocations(complete, issue(late, 2, base=1, extra_extensions=unknown_noncritical))
                          .revocation_for(Name([NameAttribute(NameOID.COMMON_NAME, 'Review issuer')]), 1))
        cases = (
            ('duplicate complete', issue(early, 1, entries=(duplicate, duplicate)), delta, 'duplicate revoked entry'),
            ('duplicate delta', complete, issue(late, 2, base=1, entries=(duplicate, duplicate)), 'duplicate revoked entry'),
            ('unknown critical CRL', issue(early, 1, extra_extensions=unknown_critical), delta, 'unsupported critical CRL extension'),
            ('unknown critical entry', complete, issue(late, 2, base=1, entries=(review_revoked_entry(1, late, extra_extensions=unknown_critical),)),
             'unsupported critical revoked-entry extension'),
            ('direct issuer extension', complete, issue(late, 2, base=1, entries=(review_revoked_entry(1, late, issuers=(name_a,)),)),
             'certificateIssuer must be critical and appear only in an indirect CRL'),
            ('noncritical issuer extension', indirect_complete,
             issue(late, 2, base=1, scope=0x84, entries=(review_revoked_entry(1, late, issuers=(name_a,), critical_issuer=False),)),
             'certificateIssuer must be critical and appear only in an indirect CRL'),
            ('issuer without DN', indirect_complete,
             issue(late, 2, base=1, scope=0x84, entries=(review_revoked_entry(1, late, issuers=(der(0x82, b'issuer.example'),)),)),
             'certificateIssuer requires a nonempty directoryName'),
            ('different AKI', issue(early, 1, authority_key=b'first'), issue(late, 2, base=1, authority_key=b'second'),
             'authority key identifiers must match'),
            ('one missing AKI', issue(early, 1, authority_key=b'first'), delta, 'authority key identifiers must match'),
            ('invalid pair rejected', complete, indirect_delta, 'same issuing distribution point scope'),
        )
        for label, base, update, error in cases:
            with self.subTest(case=label):
                with self.assertRaisesRegex(ValueError, error):
                    merge_crl_revocations(base, update, extension_schemas={'1.2.3.4': Integer})

        merge_crl_revocations(issue(early, 1, authority_key=b'match'), issue(late, 2, base=1, authority_key=b'match'))
        ambiguous = issue(late, 2, base=1, scope=0x84, entries=(review_revoked_entry(1, late, issuers=(name_a, name_b)),))
        with self.assertRaisesRegex(AmbiguousCertificateIssuer, 'supply an issuer resolver'):
            merge_crl_revocations(indirect_complete, ambiguous)
        with self.assertRaisesRegex(AmbiguousCertificateIssuer, 'must select a directoryName'):
            merge_crl_revocations(indirect_complete, ambiguous, issuer_resolver=lambda *_: Name([]))

        def choose_issuer(serial, candidates):
            self.assertEqual(serial, 1)
            self.assertEqual(len(candidates), 2)
            return candidates[1]

        snapshot = merge_crl_revocations(indirect_complete, ambiguous, issuer_resolver=choose_issuer)
        for name, present in (('Issuer A', False), ('Issuer B', True)):
            issuer = Name([NameAttribute(NameOID.COMMON_NAME, name)])
            self.assertEqual(snapshot.revocation_for(issuer, 1) is not None, present)
        COMPLETED_WITNESSES.add('crl_merge_rejections')

    def test_crl_merged_state_matches_contemporaneous_complete_crl(self):
        issue = self.crl_revision_factory()
        early, late = b'250101000000Z', b'250102000000Z'
        previous = review_revoked_entry(1, early, reason=6)
        untouched = review_revoked_entry(2, early)
        new = review_revoked_entry(3, late, reason=1, invalidity=b'20241231000000Z')
        complete = issue(early, 1, entries=(previous, untouched))
        delta = issue(late, 2, base=1, entries=(review_revoked_entry(1, late, reason=8), new))
        published = issue(late, 2, entries=(new, review_revoked_entry(2, early, reason=0)))
        merge_crl_revocations(complete, delta, published_crl=published)
        variants = (
            ('missing entry', issue(late, 2, entries=(new,)), 'differs from the published complete CRL'),
            ('extra entry', issue(late, 2, entries=(untouched, new, previous)), 'differs from the published complete CRL'),
            ('wrong reason', issue(late, 2, entries=(untouched, review_revoked_entry(3, late, reason=5, invalidity=b'20241231000000Z'))),
             'differs from the published complete CRL'),
            ('wrong revocation date', issue(late, 2, entries=(untouched, review_revoked_entry(3, early, reason=1, invalidity=b'20241231000000Z'))),
             'differs from the published complete CRL'),
            ('wrong invalidity date', issue(late, 2, entries=(untouched, review_revoked_entry(3, late, reason=1))),
             'differs from the published complete CRL'),
            ('wrong number', issue(late, 3, entries=(untouched, new)), 'delta CRL number and thisUpdate'),
            ('wrong issuer', issue(late, 2, common_name=b'Other', entries=(untouched, new)), 'same issuer name'),
            ('wrong scope', issue(late, 2, scope=0x81, entries=(untouched, new)), 'same issuing distribution point scope'),
            ('wrong time', issue(b'250103000000Z', 2, entries=(untouched, new)), 'delta CRL number and thisUpdate'),
            ('published delta', delta, 'expected a published complete CRL'),
        )
        for label, candidate, error in variants:
            with self.subTest(case=label):
                with self.assertRaisesRegex(ValueError, error):
                    merge_crl_revocations(complete, delta, published_crl=candidate)
        COMPLETED_WITNESSES.add('crl_published_state')

    def issue_crl_signer(self, *, name='Review issuer', key='signer', usage='cRLSign', serial=42, issuer_alt_name=None):
        args = ['req', '-new', '-x509', '-key', key + '.pem', '-subj', '/CN=' + name,
                '-days', '1', '-set_serial', str(serial), '-outform', 'DER',
                '-addext', 'subjectKeyIdentifier=hash', '-addext', 'basicConstraints=critical,CA:FALSE']
        if usage is not None:
            args += ['-addext', 'keyUsage=critical,' + usage]
        if issuer_alt_name is not None:
            args += ['-addext', 'issuerAltName=' + issuer_alt_name]
        return self.openssl(*args)

    def test_sm2_crl_signatures_authenticate_every_snapshot_input(self):
        issue = self.crl_revision_factory()
        early, late = b'250101000000Z', b'250102000000Z'
        issuer = self.issue_crl_signer()
        identifier = b'Certificate-revocation test ID'
        options = {'issuer_certificate': issuer, 'sm2_user_id': identifier}
        base = issue(early, 1, user_id=identifier)
        delta = issue(late, 2, base=1, user_id=identifier)
        published = issue(late, 2, user_id=identifier)
        verify_crl_signature(base, issuer, sm2_user_id=identifier)
        verify_crl_signature(issue(early, 1), issuer, sm2_user_id=USER_ID)
        verify_crl_signature(base, self.issue_crl_signer(usage=None), sm2_user_id=identifier)
        self.assertEqual(merge_crl_revocations(base, delta, published_crl=published, **options).number, 2)

        invalid_signature = 'invalid CRL signature for the authorized signing certificate'
        tampered = base.replace(early, b'250101000001Z', 1)
        self.assertNotEqual(tampered, base)
        tbs, algorithm = x509_signed_parts(base)
        r, s = sigdecode_der(load_der_x509_crl(base).signature, N)
        changed_scalar = s + 1 if s + 1 < N else s - 1
        changed_signature = der(0x30, Integer(r).dump() + Integer(changed_scalar).dump())
        changed_value = der(0x30, der(0x30, tbs) + der(0x30, algorithm) + der(0x03, b'\x00' + changed_signature))
        cases = (
            ('wrong ID', base, issuer, USER_ID, invalid_signature),
            ('missing ID', base, issuer, None, 'requires an explicit SM2 signer ID'),
            ('invalid ID type', base, issuer, 'test identity', 'requires an explicit SM2 signer ID'),
            ('ID too long', base, issuer, bytes(8192), 'requires an explicit SM2 signer ID'),
            ('wrong key same subject and serial', base, self.issue_crl_signer(key='other'), identifier, invalid_signature),
            ('wrong issuer name same key', base, self.issue_crl_signer(name='Another issuer'), identifier, 'issuer name must match'),
            ('keyUsage missing cRLSign', base, self.issue_crl_signer(usage='digitalSignature'), identifier, 'keyUsage must allow cRLSign'),
            ('changed tbsCertList', tampered, issuer, identifier, invalid_signature),
            ('changed signature scalar', changed_value, issuer, identifier, invalid_signature),
        )
        for label, crl, certificate, user_id, error in cases:
            with self.subTest(case=label):
                with self.assertRaisesRegex(ValueError, error):
                    verify_crl_signature(crl, certificate, sm2_user_id=user_id)
        self.openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'crl-wrong-curve.pem')
        wrong_curve = self.issue_crl_signer(key='crl-wrong-curve')
        with self.assertRaisesRegex(ValueError, 'id-ecPublicKey on curveSM2'):
            verify_crl_signature(base, wrong_curve, sm2_user_id=identifier)

        wrong_delta = issue(late, 2, base=1, signing_key='other', user_id=identifier)
        wrong_published = issue(late, 2, signing_key='other', user_id=identifier)
        for label, complete, update, comparison in (('base', tampered, delta, published),
                                                     ('delta', base, wrong_delta, published),
                                                     ('published', base, delta, wrong_published)):
            with self.subTest(input=label):
                with self.assertRaisesRegex(ValueError, invalid_signature):
                    merge_crl_revocations(complete, update, published_crl=comparison, **options)
        with self.assertRaisesRegex(ValueError, 'SM2 signer ID requires an issuer certificate'):
            merge_crl_revocations(base, delta, sm2_user_id=identifier)
        COMPLETED_WITNESSES.add('crl_signature_authentication')

    def test_crl_signer_identifier_binds_signing_certificate_metadata(self):
        issue = self.crl_revision_factory()
        early, late = b'250101000000Z', b'250102000000Z'
        certificate = self.issue_crl_signer(issuer_alt_name='DNS:issuer.example')
        signer = load_der_x509_certificate(certificate)
        key_id = signer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        issuer_dn = der(0xa4, signer.issuer.public_bytes())
        other_dn = der(0xa4, der(0x30, common_name_rdn(b'Other issuer')))
        cases = (
            ('key identifier only', der(0x80, key_id), None),
            ('issuer and serial only', der(0xa1, issuer_dn) + der(0x82, b'\x2a'), None),
            ('issuer alternative and serial', der(0xa1, der(0x82, b'issuer.example')) + der(0x82, b'\x2a'), None),
            ('both identifier forms', der(0x80, key_id) + der(0xa1, issuer_dn) + der(0x82, b'\x2a'), None),
            ('wrong key identifier', der(0x80, b'different key identifier'), 'must match the signing certificate subject key identifier'),
            ('wrong serial only', der(0xa1, issuer_dn) + der(0x82, b'\x2b'), 'issuer and serial must match'),
            ('wrong issuer only', der(0xa1, other_dn) + der(0x82, b'\x2a'), 'issuer and serial must match'),
        )
        for label, fields, error in cases:
            ext = x509_extension('2.5.29.35', der(0x30, fields))
            complete = issue(early, 1, extra_extensions=ext)
            delta = issue(late, 2, base=1, extra_extensions=ext)
            with self.subTest(case=label):
                if error is None:
                    merge_crl_revocations(complete, delta, issuer_certificate=certificate, sm2_user_id=USER_ID)
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        merge_crl_revocations(complete, delta, issuer_certificate=certificate, sm2_user_id=USER_ID)
        COMPLETED_WITNESSES.add('crl_signer_identifier')

    def test_openssl_independently_agrees_on_certificate_revocation(self):
        early = datetime(2025, 1, 1, tzinfo=timezone.utc)
        late = early + timedelta(days=1)
        expiry = late + timedelta(days=3)
        eval_time = str(int((late + timedelta(days=1)).timestamp()))
        pem, encoded_der = serialization.Encoding.PEM, serialization.Encoding.DER
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        issuer = Name([NameAttribute(NameOID.COMMON_NAME, 'Test-only delta CA')])
        ski = x509.SubjectKeyIdentifier.from_public_key(signing_key.public_key())
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
        point = x509.DistributionPoint([x509.UniformResourceIdentifier('http://example.invalid/delta.crl')],
                                        None, None, None)

        def certificate(subject, serial, *, ca=False):
            builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).serial_number(serial)
                       .public_key(signing_key.public_key() if ca else leaf_key).not_valid_before(early - timedelta(days=1))
                       .not_valid_after(expiry).add_extension(x509.BasicConstraints(ca, None), critical=True)
                       .add_extension(aki, critical=False))
            if ca:
                usage = x509.KeyUsage(False, False, False, False, False, True, True, None, None)
                builder = builder.add_extension(ski, critical=False).add_extension(usage, critical=True)
            return builder.sign(signing_key, hashes.SHA256())

        def crl(number, date, entries, *, delta_base=None):
            builder = (x509.CertificateRevocationListBuilder().issuer_name(issuer).last_update(date).next_update(expiry)
                       .add_extension(x509.CRLNumber(number), critical=False).add_extension(aki, critical=False))
            if delta_base is None:
                builder = builder.add_extension(x509.FreshestCRL([point]), critical=False)
            else:
                builder = builder.add_extension(x509.DeltaCRLIndicator(delta_base), critical=True)
            for serial, revoked_at, reason in entries:
                entry = (x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(revoked_at)
                         .add_extension(x509.CRLReason(reason), critical=False).build())
                builder = builder.add_revoked_certificate(entry)
            return builder.sign(signing_key, hashes.SHA256())

        hold, remove = ReasonFlags.certificate_hold, ReasonFlags.remove_from_crl
        compromise, superseded = ReasonFlags.key_compromise, ReasonFlags.superseded
        base = crl(11, early, ((101, early, hold), (102, early, compromise), (104, early, hold)))
        delta = crl(12, late, ((101, late, remove), (103, late, compromise), (104, late, superseded), (105, late, remove)),
                    delta_base=11)
        published = crl(12, late, ((102, early, compromise), (103, late, compromise), (104, late, superseded)))
        issuer_certificate = certificate(issuer, 1, ca=True)
        (self.directory / 'root.pem').write_bytes(issuer_certificate.public_bytes(pem))
        for label, item in (('base.pem', base), ('delta.pem', delta), ('latest.pem', published)):
            (self.directory / label).write_bytes(item.public_bytes(pem))
            verified = subprocess.run(['openssl', 'crl', '-verify', '-CAfile', 'root.pem', '-in', label, '-noout'],
                                      cwd=self.directory, capture_output=True, check=True, timeout=15)
            self.assertIn(b'verify OK', verified.stderr)
        (self.directory / 'series.pem').write_bytes(base.public_bytes(pem) + delta.public_bytes(pem))
        snapshot = merge_crl_revocations(base.public_bytes(encoded_der), delta.public_bytes(encoded_der),
                                         published_crl=published.public_bytes(encoded_der),
                                         issuer_certificate=issuer_certificate.public_bytes(encoded_der))
        cases = ((101, True, None), (102, True, compromise), (103, False, compromise), (104, True, superseded),
                 (105, False, None), (106, False, None))
        for serial, previously_revoked, expected_reason in cases:
            subject = Name([NameAttribute(NameOID.COMMON_NAME, f'Test-only leaf {serial}')])
            (self.directory / 'leaf.pem').write_bytes(certificate(subject, serial).public_bytes(pem))
            recovered = snapshot.revocation_for(issuer, serial)
            self.assertEqual(recovered.reason if recovered is not None else None, expected_reason)
            for file, expected, flags in (('base.pem', previously_revoked, ()),
                                          ('series.pem', expected_reason is not None, ('-extended_crl', '-use_deltas')),
                                          ('latest.pem', expected_reason is not None, ())):
                with self.subTest(serial=serial, crls=file):
                    checked = subprocess.run(['openssl', 'verify', '-crl_check', *flags, '-attime', eval_time,
                                              '-CAfile', 'root.pem', '-CRLfile', file, 'leaf.pem'],
                                             cwd=self.directory, capture_output=True, timeout=15)
                    if expected:
                        self.assertNotEqual(checked.returncode, 0)
                        self.assertIn(b'certificate revoked', checked.stderr)
                    else:
                        self.assertEqual(checked.returncode, 0, checked.stderr)
        COMPLETED_WITNESSES.add('crl_openssl_state')

    def test_crl_issuer_revoked_sequence_and_implicit_flags(self):
        _, crl = self.issue_certificate_and_crl(version_2_crl=True)
        body, algorithm = x509_signed_parts(crl)
        version, signature, issuer, current, next_update, *_ = encoded_fields(body)
        prefix = version + signature + issuer + current + next_update
        number = x509_extension('2.5.29.20', der(0x02, b'\x01'))

        def revoked(date):
            return der(0x30, der(0x30, der(0x02, b'\x01') + date))

        cases = [
            ('empty revoked list omitted', prefix, b'', None),
            ('empty revoked list present', prefix + der(0x30, b''), b'', 'revokedCertificates must be omitted'),
            ('revocation has DER UTC time', prefix + revoked(der(0x17, b'251231000000Z')), b'', None),
            ('revocation has offset', prefix + revoked(der(0x17, b'251231000000+0000')), b'', 'expected UTC with seconds'),
            ('revocation has no seconds', prefix + revoked(der(0x17, b'2512310000Z')), b'', 'expected UTC with seconds'),
            ('issuer has empty RDN', version + signature + der(0x30, der(0x31, b'')) + current + next_update,
             b'', 'empty DER issuer RDN'),
        ]
        for tag in (0x81, 0x82, 0x84, 0x85):
            for value, error in ((b'\xff', None), (b'\x00', 'BOOLEAN flags must be TRUE or omitted'),
                                 (b'\x01', 'BOOLEAN flags must be TRUE or omitted')):
                distribution = x509_extension('2.5.29.28', der(0x30, der(tag, value)), critical=True)
                cases.append((f'issuing distribution flag {tag:#x}={value.hex()}', prefix, distribution, error))
        self.assertEqual(len(cases), 18)
        for label, fields, extension, error in cases:
            member = self.sign_review_metadata(fields + der(0xa0, der(0x30, number + extension)), algorithm)
            envelope = signed_data(self.signatures['direct'], attached=MESSAGE, include_signer=False,
                                   digest_algorithms=b'', metadata=der(0xa1, member))
            with self.subTest(case=label):
                if error is None:
                    validate_signed_data_format(envelope)
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        validate_signed_data_format(envelope)
        COMPLETED_WITNESSES.add('crl_field_encoding')

    def test_chapter_8_freshest_crl_and_revoked_entry_constraints(self):
        _, crl = self.issue_certificate_and_crl(version_2_crl=True)
        body, algorithm = x509_signed_parts(crl)
        prefix = b''.join(tuple(encoded_fields(body))[:5])

        def extension(number, value, *, critical=False):
            critical_field = der(0x01, b'\xff') if critical else b''
            return der(0x30, der(0x06, bytes((0x55, 0x1d, number))) + critical_field + der(0x04, value))

        def freshest(point_fields, *, critical=False):
            return extension(46, der(0x30, der(0x30, point_fields)), critical=critical)

        def reason(number, *, critical=False):
            return extension(21, der(0x0a, bytes((number,))), critical=critical)

        distribution_point = der(0xa0, der(0xa0, der(0x86, b'https://example.org/delta.crl')))
        freshest_crl = freshest(distribution_point)
        number = extension(20, der(0x02, b'\x09'))
        delta = extension(27, der(0x02, b'\x08'), critical=True)
        invalidity_date = der(0x18, b'20251230235959Z')
        cases = (
            ('complete CRL points to delta', freshest_crl, reason(1) + extension(24, invalidity_date), b'\x02', None),
            ('removeFromCRL on delta', delta, reason(8), b'\x02', None),
            ('critical freshestCRL', freshest(distribution_point, critical=True), b'', b'\x02',
             'freshestCRL must be noncritical'),
            ('freshestCRL on delta', freshest_crl + delta, b'', b'\x02', 'freshestCRL must not appear on a delta CRL'),
            ('empty freshestCRL', extension(46, der(0x30, b'')), b'', b'\x02',
             'freshestCRL must contain at least one distribution point'),
            ('freshestCRL reasons', freshest(distribution_point + der(0x81, b'\x06\x40')), b'', b'\x02',
             'must omit reasons and cRLIssuer'),
            ('freshestCRL issuer', freshest(distribution_point + der(0xa2, der(0x82, b'issuer.example'))), b'', b'\x02',
             'must omit reasons and cRLIssuer'),
            ('removeFromCRL on complete', b'', reason(8), b'\x02', 'removeFromCRL requires a delta CRL'),
            ('critical reasonCode', b'', reason(1, critical=True), b'\x02', 'reasonCode must be noncritical'),
            ('critical invalidityDate', b'', extension(24, invalidity_date, critical=True), b'\x02',
             'invalidityDate must be noncritical'),
            ('empty certificateIssuer', b'', extension(29, der(0x30, b'')), b'\x02', 'certificateIssuer must contain'),
            ('zero revoked serial', b'', b'', b'\x00', 'revoked certificate serial number must be positive'),
            ('oversized revoked serial', b'', b'', b'\x00\x80' + bytes(19), 'at most 20 DER octets'),
        )
        for label, crl_extensions, entry_extensions, serial, error in cases:
            entry = der(0x02, serial) + der(0x17, b'251231000000Z')
            if entry_extensions:
                entry += der(0x30, entry_extensions)
            encoded = prefix + der(0x30, der(0x30, entry)) + der(0xa0, der(0x30, number + crl_extensions))
            member = self.sign_review_metadata(encoded, algorithm)
            envelope = signed_data(self.signatures['direct'], attached=MESSAGE, include_signer=False,
                                   digest_algorithms=b'', metadata=der(0xa1, member))
            with self.subTest(case=label):
                if error is None:
                    validate_signed_data_format(envelope)
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        validate_signed_data_format(envelope)
        COMPLETED_WITNESSES.add('crl_entry_profile')

    def test_typed_der_for_private_certificate_crl_and_revoked_entry_extensions(self):
        class IntegerSet(SetOf):
            _child_spec = Integer

        certificate, crl = self.issue_certificate_and_crl(version_2_crl=True)
        cert_body, cert_algorithm = x509_signed_parts(certificate)
        crl_body, crl_algorithm = x509_signed_parts(crl)
        cert_prefix = b''.join(tuple(encoded_fields(cert_body))[:7])
        crl_prefix = b''.join(tuple(encoded_fields(crl_body))[:5])
        revoked_entry = der(0x02, b'\x02') + der(0x17, b'251231000000Z')
        contexts = (
            ('certificate', 0xa0, cert_algorithm, lambda field: cert_prefix + der(0xa3, field)),
            ('CRL', 0xa1, crl_algorithm, lambda field: crl_prefix + der(0xa0, field)),
            ('CRL entry', 0xa1, crl_algorithm,
             lambda field: crl_prefix + der(0x30, der(0x30, revoked_entry + field))),
        )
        first, second = der(0x02, b'\x01'), der(0x02, b'\x02')
        cases = (
            ('canonical SET OF', der(0x31, first + second), True),
            ('wrong SET OF order', der(0x31, second + first), False),
            ('wrong ASN.1 value type', der(0x04, b'test-only'), False),
        )
        oid = der(0x06, bytes.fromhex('2a0307'))
        schemas = {'1.2.3.7': IntegerSet}
        for kind, tag, algorithm, build in contexts:
            for case, value, conforming in cases:
                extension = der(0x30, oid + der(0x04, value))
                encoded = self.sign_review_metadata(build(der(0x30, extension)), algorithm)
                envelope = signed_data(self.signatures['direct'], attached=MESSAGE, include_signer=False,
                                       digest_algorithms=b'', metadata=der(tag, encoded))
                with self.subTest(kind=kind, case=case):
                    validate_signed_data_format(envelope)
                    with self.assertRaisesRegex(MissingExtensionSchema, r'1\.2\.3\.7'):
                        validate_signed_data_format(envelope, extension_schemas={})
                    if conforming:
                        validate_signed_data_format(envelope, extension_schemas=schemas)
                    else:
                        with self.assertRaisesRegex(ValueError, r'invalid DER value for X.509 extension 1\.2\.3\.7'):
                            validate_signed_data_format(envelope, extension_schemas=schemas)
        COMPLETED_WITNESSES.add('extension_schemas')

    def test_explicit_signed_attrs_encodings_have_separate_signature_inputs(self):
        for tag, other_tag, encoding, other_encoding in (
            (0x31, 0xa0, 'cms-set', 'context-field'),
            (0xa0, 0x31, 'context-field', 'cms-set'),
        ):
            payload = der(tag, self.attribute)
            signature = self.external_signature(payload)
            self.assertTrue(self.external_verify(signature, payload))
            self.assertFalse(self.external_verify(signature, der(other_tag, self.attribute)))
            for attached in (None, MESSAGE):
                with self.subTest(encoding=encoding, attached=attached is not None):
                    detached = MESSAGE if attached is None else None
                    envelope = signed_data(signature, attached=attached, signed_attrs=self.attributes)
                    validate_signed_data_format(envelope)
                    self.assertEqual(verify_signed_data(envelope, self.trusted_signers,
                                                        detached_content=detached, signed_attrs_encoding=encoding),
                                     MESSAGE)
                    with self.assertRaisesRegex(ValueError, 'invalid SignedData signature'):
                        verify_signed_data(envelope, self.trusted_signers,
                                           detached_content=detached, signed_attrs_encoding=other_encoding)
                    with self.assertRaisesRegex(ValueError, 'expected cms-set or context-field'):
                        verify_signed_data(envelope, self.trusted_signers,
                                           detached_content=detached, signed_attrs_encoding='auto')
        COMPLETED_WITNESSES.add('signed_attrs_encoding')

    def test_envelope_algorithm_parameter_interoperability_domain(self):
        digest_oids = (bytes.fromhex('06082a811ccf55018311'), bytes.fromhex('06092a811ccf5501831101'))
        signature_oid = bytes.fromhex('06092a811ccf5501822d01')
        digest_identifiers = tuple(der(0x30, oid + params) for oid, params in product(digest_oids, (b'', NULL)))
        signature_identifiers = tuple(der(0x30, signature_oid + params) for params in (b'', NULL))
        cases = tuple(product(digest_identifiers, digest_identifiers, signature_identifiers))
        self.assertEqual(len(set(cases)), 32)
        for outer, inner, signer_algorithm in cases:
            with self.subTest(outer=outer.hex(), inner=inner.hex(), signature=signer_algorithm.hex()):
                envelope = signed_data(self.signatures['direct'], attached=MESSAGE, digest_algorithms=outer,
                                       signer_digest=inner, algorithm=signer_algorithm)
                validate_signed_data_format(envelope)
                self.assertEqual(self.verify_attached(envelope), MESSAGE)
                self.assertEqual(self.apply_adapter(envelope), self.raw_direct)
        for field, oid in (('digest_algorithms', digest_oids[0]), ('signer_digest', digest_oids[1]),
                           ('algorithm', signature_oid)):
            for parameters in (der(0x05, b'\x01'), der(0x04, b'')):
                envelope = signed_data(self.signatures['direct'], attached=MESSAGE,
                                       **{field: der(0x30, oid + parameters)})
                for check in (validate_signed_data_format, self.verify_attached, self.apply_adapter):
                    with self.subTest(field=field, params=parameters.hex(), entry_point=check.__name__):
                        with self.assertRaises(ValueError):
                            check(envelope)
        COMPLETED_WITNESSES.add('envelope_parameters')

    def check_extension_envelope(self, tag, body, algorithm, error=None):
        encoded = self.sign_review_metadata(body, algorithm)
        envelope = signed_data(self.signatures['direct'], attached=MESSAGE, metadata=der(tag, encoded))
        for verify, result in ((self.apply_adapter, self.raw_direct), (self.verify_attached, MESSAGE)):
            with self.subTest(entry_point=verify.__name__):
                if error is None:
                    self.assertEqual(verify(envelope), result)
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        verify(envelope)


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
