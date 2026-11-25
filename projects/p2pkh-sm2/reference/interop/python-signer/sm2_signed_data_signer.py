#!/usr/bin/env python3
"""Test-only GB/T 35275-2026 signer backed by OpenSSL SM2/SM3."""

import argparse
import json
import subprocess
from binascii import Error, unhexlify
from pathlib import Path
from tempfile import TemporaryDirectory

from asn1crypto import core
from asn1crypto.keys import PublicKeyInfo
from asn1crypto.x509 import Name


USER_ID = '1234567812345678'
CURVE_OID = '1.2.156.10197.1.301'
CURVE_ORDER = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
DATA_OID = '1.2.156.10197.6.1.4.2.1'
SIGNED_DATA_OID = '1.2.156.10197.6.1.4.2.2'
SM3_UNKEYED_OID = '1.2.156.10197.1.401.1'
SM2_SIGNATURE_OID = '1.2.156.10197.1.301.1'
SIGNER_VERSION = 2


class ECPrivateKey(core.Sequence):
    _fields = [
        ('version', core.Integer),
        ('private_key', core.OctetString),
        ('parameters', core.ObjectIdentifier, {'explicit': 0}),
    ]


class AlgorithmIdentifier(core.Sequence):
    _fields = [('algorithm', core.ObjectIdentifier)]


class DigestAlgorithms(core.SetOf):
    _child_spec = AlgorithmIdentifier


class EncapsulatedContentInfo(core.Sequence):
    _fields = [
        ('content_type', core.ObjectIdentifier),
        ('content', core.OctetString, {'explicit': 0, 'optional': True}),
    ]


class IssuerAndSerialNumber(core.Sequence):
    _fields = [('issuer', Name), ('serial_number', core.Integer)]


class SignerInfo(core.Sequence):
    _fields = [
        ('version', core.Integer),
        ('signer_identifier', IssuerAndSerialNumber),
        ('digest_algorithm', AlgorithmIdentifier),
        ('signature_algorithm', AlgorithmIdentifier),
        ('signature', core.OctetString),
    ]


class SignerInfos(core.SetOf):
    _child_spec = SignerInfo


class SignedData(core.Sequence):
    _fields = [
        ('version', core.Integer),
        ('digest_algorithms', DigestAlgorithms),
        ('content', EncapsulatedContentInfo),
        ('signer_infos', SignerInfos),
    ]


class ContentInfo(core.Sequence):
    _fields = [
        ('content_type', core.ObjectIdentifier),
        ('content', SignedData, {'explicit': 0}),
    ]


def sign(message, key, detached):
    if not message:
        raise ValueError('message must not be empty')
    if len(key) != 32 or not 1 <= int.from_bytes(key, 'big') < CURVE_ORDER - 1:
        raise ValueError('invalid 32-byte SM2 test key')
    private_key = ECPrivateKey({'version': 1, 'private_key': key, 'parameters': CURVE_OID})
    with TemporaryDirectory() as directory:
        path = Path(directory)
        (path / 'key.der').write_bytes(private_key.dump())
        (path / 'message').write_bytes(message)
        public_der = subprocess.check_output([
            'openssl', 'pkey', '-inform', 'DER', '-in', 'key.der', '-pubout', '-outform', 'DER',
        ], cwd=path)
        signature = subprocess.check_output([
            'openssl', 'pkeyutl', '-sign', '-rawin', '-digest', 'sm3', '-keyform', 'DER',
            '-inkey', 'key.der', '-pkeyopt', 'distid:' + USER_ID, '-in', 'message',
        ], cwd=path)
    public_key = PublicKeyInfo.load(public_der)['public_key'].native
    if len(public_key) != 65 or public_key[0] != 4:
        raise ValueError('expected an uncompressed SM2 public key')

    # Keep the exact fixture identifier used by the Rust signer and its predecessor.
    signer_identifier = IssuerAndSerialNumber({
        'issuer': Name.build({
            'organization_name': 'BSV Script Lab',
            'common_name': 'Independent Go Signer',
        }, use_printable=True),
        'serial_number': 1,
    })
    digest = {'algorithm': SM3_UNKEYED_OID}
    content = {'content_type': DATA_OID}
    if not detached:
        content['content'] = message
    envelope = ContentInfo({
        'content_type': SIGNED_DATA_OID,
        'content': {
            'version': 1,
            'digest_algorithms': [digest],
            'content': content,
            'signer_infos': [{
                'version': SIGNER_VERSION,
                'signer_identifier': signer_identifier,
                'digest_algorithm': digest,
                'signature_algorithm': {'algorithm': SM2_SIGNATURE_OID},
                'signature': signature,
            }],
        },
    })
    return {
        'envelope_hex': envelope.dump().hex(),
        'public_key_hex': public_key.hex(),
        'signer_identifier_hex': signer_identifier.dump().hex(),
        'signer_version': SIGNER_VERSION,
    }


def hex_bytes(value):
    try:
        return unhexlify(value)
    except (Error, ValueError) as error:
        raise argparse.ArgumentTypeError('expected hexadecimal bytes') from error


def detached_flag(value):
    if value.lower() in ('true', 't', '1'):
        return True
    if value.lower() in ('false', 'f', '0'):
        return False
    raise argparse.ArgumentTypeError('expected a boolean')


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('-message', '--message', required=True, type=hex_bytes, metavar='HEX')
    parser.add_argument('-key', '--key', required=True, type=hex_bytes, metavar='TEST_KEY_HEX')
    parser.add_argument('-detached', '--detached', nargs='?', const=True, default=False,
                        type=detached_flag)
    args = parser.parse_args()
    try:
        response = sign(args.message, args.key, args.detached)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{error}\n')
    print(json.dumps(response))


if __name__ == '__main__':
    main()
