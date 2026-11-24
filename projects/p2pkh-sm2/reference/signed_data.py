"""SM2 SignedData verification and the direct payment adapter."""

from asn1crypto.core import ObjectIdentifier
from asn1crypto.x509 import Certificate as ASN1Certificate
from cryptography.x509 import UnsupportedGeneralNameType, load_der_x509_certificate, load_der_x509_crl

from sm2 import N, USER_ID, be32, parse_public, sm3, verify


_DATA = bytes.fromhex('2a811ccf550601040201')
_SIGNED_DATA = bytes.fromhex('2a811ccf550601040202')
_SM3 = bytes.fromhex('2a811ccf55018311')
_SM3_UNKEYED = bytes.fromhex('2a811ccf5501831101')
_SM2_SIGNATURE = bytes.fromhex('2a811ccf5501822d01')
_SM2_WITH_SM3 = bytes.fromhex('2a811ccf55018375')
_MESSAGE_DIGEST = bytes.fromhex('2a864886f70d010904')
_NUMERIC_STRING = b' 0123456789'
_PRINTABLE_STRING = (b" '()+,-./:=?0123456789"
                     b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
# X.690 §10.2 forbids the constructed encoding of restricted character strings.
_CONSTRUCTED_CHARACTER_STRINGS = frozenset((
    0x2c,                          # UTF8String
    0x32, 0x33, 0x34, 0x35, 0x36,   # NumericString through IA5String
    0x39, 0x3a, 0x3b, 0x3c, 0x3e,   # GraphicString through UniversalString, then BMPString
))


class _DER:
    def __init__(self, data):
        self.data = data
        self.position = 0

    def next_is(self, tag):
        return self.position < len(self.data) and self.data[self.position] == tag

    def take(self, tag=None):
        start = self.position
        if start == len(self.data) or (tag is not None and not self.next_is(tag)):
            raise ValueError('unexpected or truncated SignedData DER field')
        first = self.data[start]
        length_at = start + 1
        if first in (0x00, 0x20):
            raise ValueError('invalid DER tag')
        if first & 0x1f == 0x1f:
            if length_at == len(self.data) or self.data[length_at] < 31 or self.data[length_at] == 0x80:
                raise ValueError('invalid DER tag')
            while length_at < len(self.data) and self.data[length_at] & 0x80:
                length_at += 1
            length_at += 1
        if length_at >= len(self.data):
            raise ValueError('unexpected or truncated SignedData DER field')
        length = self.data[length_at]
        content = length_at + 1
        if length >= 128:
            width = length & 127
            encoded_length = self.data[content:content + width]
            if not width or len(encoded_length) != width or encoded_length[0] == 0:
                raise ValueError('invalid DER length')
            length = int.from_bytes(encoded_length, 'big')
            if length < 128:
                raise ValueError('non-minimal DER length')
            content += width
        end = content + length
        if end > len(self.data):
            raise ValueError('truncated DER content')
        self.position = end
        return self.data[content:end]

    def done(self):
        if self.position != len(self.data):
            raise ValueError('trailing or unsupported SignedData fields')

    def take_encoded(self, tag=None):
        start = self.position
        self.take(tag)
        return self.data[start:self.position]


class MissingAttributeSchema(ValueError):
    """An AttributeValue's declared ASN.1 type is unavailable."""


def _algorithm(fields, *allowed):
    algorithm = _DER(fields.take(0x30))
    if algorithm.take(0x06) not in allowed:
        raise ValueError('unexpected SignedData algorithm')
    # AlgorithmIdentifier permits an omitted parameters field. The SM3 and
    # SM2-1 identifiers in GB/T 35275-2026 Appendix A.1 use explicit NULL.
    if algorithm.next_is(0x05) and algorithm.take(0x05):
        raise ValueError('invalid DER NULL parameters')
    algorithm.done()


def _digest_algorithm(fields):
    _algorithm(fields, _SM3, _SM3_UNKEYED)


def _minimal_integer(value):
    if len(value) < 2:
        return bool(value)
    return not (value[0] == 0 and value[1] < 0x80
                or value[0] == 0xff and value[1] >= 0x80)


def _signature(der):
    outer = _DER(der)
    values = _DER(outer.take(0x30))
    outer.done()
    signature = bytearray()
    for _ in range(2):
        integer = values.take(0x02)
        if not _minimal_integer(integer) or len(integer) > 33 or integer[0] & 0x80:
            raise ValueError('invalid DER SM2 scalar')
        scalar = int.from_bytes(integer, 'big')
        if not 1 <= scalar < N:
            raise ValueError('SM2 scalar outside the curve order')
        signature += be32(scalar)
    values.done()
    return bytes(signature)


def _check_issuer_and_serial_number(identifier):
    outer = _DER(identifier)
    fields = _DER(outer.take(0x30))
    outer.done()
    try:
        _check_issuer_name(fields.take(0x30))
    except ValueError as error:
        raise ValueError(f'invalid DER issuer Name: {error}') from error
    serial = fields.take(0x02)
    if not _minimal_integer(serial) or serial[0] & 0x80 or not any(serial):
        raise ValueError('expected a positive DER certificate serial number')
    fields.done()


def _check_issuer_name(encoded):
    if not encoded:
        raise ValueError('empty DER issuer Name')
    name = _DER(encoded)
    while name.position < len(name.data):
        rdn = name.take(0x31)
        if not rdn:
            raise ValueError('empty DER issuer RDN')
        for member in _set_members(rdn, 0x30):
            attribute = _DER(_DER(member).take(0x30))
            _check_oid(attribute.take(0x06))
            _check_open_value(attribute.take_encoded())
            attribute.done()


def _set_members(content, tag=None):
    fields = _DER(content)
    previous = b''
    while fields.position < len(content):
        encoded = fields.take_encoded(tag)
        if encoded < previous:
            raise ValueError('DER SET OF members out of order')
        yield encoded
        previous = encoded


def _check_oid(oid, name='attribute OID'):
    if (not oid or oid[-1] & 0x80
            or any(octet == 0x80 and (index == 0 or oid[index - 1] < 0x80)
                   for index, octet in enumerate(oid))):
        raise ValueError(f'invalid DER {name}')


def _check_bit_string(value):
    if not value or value[0] > 7:
        raise ValueError('invalid DER BIT STRING')
    unused = value[0]
    if unused and (len(value) == 1 or value[-1] & ((1 << unused) - 1)):
        raise ValueError('invalid DER BIT STRING')


def _check_open_value(encoded):
    # Walk nested TLVs iteratively. Attribute-specific value syntax remains
    # determined by the OID, outside the payment adapter.
    pending = [_DER(memoryview(encoded))]
    while pending:
        fields = pending.pop()
        while fields.position < len(fields.data):
            tag = fields.data[fields.position]
            value = fields.take()
            if tag == 0x21 or (tag == 0x01 and value not in (b'\x00', b'\xff')):
                raise ValueError('invalid DER BOOLEAN')
            if tag == 0x22 or (tag == 0x02 and not _minimal_integer(value)):
                raise ValueError('invalid DER INTEGER')
            if tag == 0x03:
                _check_bit_string(value)
            if tag == 0x23:
                raise ValueError('invalid DER BIT STRING')
            if tag == 0x24:
                raise ValueError('invalid DER OCTET STRING')
            if tag == 0x25 or (tag == 0x05 and value):
                raise ValueError('invalid DER NULL')
            if tag == 0x06:
                _check_oid(value)
            if tag == 0x26:
                raise ValueError('invalid DER attribute OID')
            if tag == 0x0d:
                _check_oid(value, 'RELATIVE-OID')
            if tag == 0x2d:
                raise ValueError('invalid DER RELATIVE-OID')
            if tag == 0x2a or (tag == 0x0a and not _minimal_integer(value)):
                raise ValueError('invalid DER ENUMERATED')
            if tag in (0x10, 0x11):
                raise ValueError('DER SEQUENCE and SET must be constructed')
            if tag in _CONSTRUCTED_CHARACTER_STRINGS:
                raise ValueError('DER character strings must be primitive')
            if tag == 0x0c:
                try:
                    bytes(value).decode('utf-8')
                except UnicodeDecodeError as error:
                    raise ValueError('invalid DER UTF8String') from error
            if tag == 0x12 and any(octet not in _NUMERIC_STRING for octet in value):
                raise ValueError('invalid DER NumericString')
            if tag == 0x13 and any(octet not in _PRINTABLE_STRING for octet in value):
                raise ValueError('invalid DER PrintableString')
            if tag == 0x16 and not bytes(value).isascii():
                raise ValueError('invalid DER IA5String')
            if tag == 0x1a and any(not 0x20 <= octet <= 0x7e for octet in value):
                raise ValueError('invalid DER VisibleString')
            if tag in (0x17, 0x18):
                _check_der_time(tag, bytes(value))
            if tag in (0x37, 0x38):
                raise ValueError('DER times must be primitive')
            if tag & 0x20:
                pending.append(_DER(value))


def _check_attribute_schema(oid, values, schemas):
    if oid == _MESSAGE_DIGEST:
        if len(values) != 1:
            raise ValueError('messageDigest must have one OCTET STRING value')
        digest = _DER(values[0])
        if len(digest.take(0x04)) != 32:
            raise ValueError('messageDigest must contain 32 SM3 octets')
        digest.done()
        return

    identifier = ObjectIdentifier(contents=oid).dotted
    schema = schemas.get(identifier)
    if schema is None:
        raise MissingAttributeSchema(f'missing ASN.1 schema for SignedData attribute {identifier}')
    for encoded in values:
        try:
            value = schema.load(encoded, strict=True)
            if value.dump(force=True) != encoded:
                raise ValueError('value is not the canonical encoding of its ASN.1 type')
        except ValueError as error:
            raise ValueError(f'invalid DER value for SignedData attribute {identifier}: {error}') from error


def _attribute(encoded, schemas=None):
    attribute = _DER(_DER(encoded).take(0x30))
    oid = attribute.take(0x06)
    _check_oid(oid)
    values = tuple(_set_members(attribute.take(0x31)))
    for value in values:
        _check_open_value(value)
    attribute.done()
    if schemas is not None:
        _check_attribute_schema(oid, values, schemas)
    return oid, values


def _check_x509_signature(tbs, outer):
    inner = tbs.take_encoded(0x30)
    if inner != outer.take_encoded(0x30):
        raise ValueError('inner and outer signature algorithm identifiers differ')
    algorithm = _DER(_DER(inner).take(0x30))
    oid = algorithm.take(0x06)
    if oid in (_SM2_SIGNATURE, _SM2_WITH_SM3):
        if algorithm.position != len(algorithm.data):
            raise ValueError('SM2 certificate and CRL signature algorithm parameters must be absent')
        signature_bits = outer.take(0x03)
        if not signature_bits or signature_bits[0] != 0:
            raise ValueError('SM2 certificate and CRL signature BIT STRING must be octet-aligned')
        try:
            _signature(signature_bits[1:])
        except ValueError as error:
            raise ValueError(f'invalid X.509 SM2Signature: {error}') from error


def _check_der_time(tag, value, *, allow_fraction=True):
    digits, point, fraction = value[:-1].partition(b'.')
    utc = tag == 0x17
    if len(digits) != (12 if utc else 14) or value[-1:] != b'Z' or not digits.isdigit():
        raise ValueError('invalid DER time encoding, expected UTC with seconds')
    if point and (utc or not allow_fraction or not fraction.isdigit() or fraction.endswith(b'0')):
        raise ValueError('invalid DER time fraction')


def _check_x509_time(fields):
    tag = 0x17 if fields.next_is(0x17) else 0x18
    value = fields.take(tag)
    try:
        _check_der_time(tag, value, allow_fraction=False)
    except ValueError as error:
        raise ValueError(f'invalid X.509 time encoding: {error}') from error
    if tag == 0x18 and value[:4] < b'2050':
        raise ValueError('X.509 dates before 2050 must use UTCTime')


def _check_extensions(encoded):
    outer = _DER(encoded)
    extensions = _DER(outer.take(0x30))
    outer.done()
    seen = set()
    while extensions.position < len(extensions.data):
        entry = _DER(extensions.take(0x30))
        oid = entry.take(0x06)
        _check_oid(oid, 'extension OID')
        if oid in seen:
            raise ValueError('duplicate X.509 extension OID')
        seen.add(oid)
        if entry.next_is(0x01) and entry.take(0x01) != b'\xff':
            raise ValueError('X.509 extension critical must be TRUE or omitted')
        value = _DER(entry.take(0x04))
        _check_open_value(value.take_encoded())
        value.done()
        entry.done()
    if not seen:
        raise ValueError('empty X.509 Extensions')


def _check_certificate(encoded):
    fields = _DER(_DER(encoded).take(0x30))
    tbs = _DER(fields.take(0x30))
    version = b'\x00'
    if tbs.next_is(0xa0):
        version_field = _DER(tbs.take(0xa0))
        version = version_field.take(0x02)
        version_field.done()
        if version not in (b'\x01', b'\x02'):
            raise ValueError('expected certificate v2, v3, or omitted v1 default')
    serial = tbs.take(0x02)
    if not _minimal_integer(serial) or serial[0] & 0x80 or not any(serial) or len(serial) > 20:
        raise ValueError('expected a positive certificate serial number of at most 20 octets')
    _check_x509_signature(tbs, fields)
    issuer = tbs.take(0x30)
    if not issuer:
        raise ValueError('empty certificate issuer Name')
    _check_issuer_name(issuer)
    validity = _DER(tbs.take(0x30))
    _check_x509_time(validity)  # notBefore.
    _check_x509_time(validity)  # notAfter.
    validity.done()
    tbs.take(0x30)  # Subject.
    tbs.take(0x30)  # SubjectPublicKeyInfo.
    for identifier_tag in (0x81, 0x82):
        if tbs.next_is(identifier_tag):
            if version == b'\x00':
                raise ValueError('certificate unique identifiers require v2 or v3')
            _check_bit_string(tbs.take(identifier_tag))
    if tbs.next_is(0xa3):
        if version != b'\x02':
            raise ValueError('certificate extensions require v3')
        _check_extensions(tbs.take(0xa3))
    tbs.done()
    if version == b'\x01':
        # GB/T 20518 permits v2, which cryptography's certificate loader rejects.
        # Decode the original bytes, including the unique identifier fields.
        ASN1Certificate.load(encoded, strict=True).native
        return
    certificate = load_der_x509_certificate(encoded)
    if not certificate.issuer.rdns:
        raise ValueError('empty certificate issuer Name')
    try:
        # The X.509 decoder parses known extension values on access.
        certificate.extensions
    except UnsupportedGeneralNameType as error:
        raise ValueError(f'invalid X.509 certificate extension: {error}') from error


def _check_crl(encoded):
    fields = _DER(_DER(encoded).take(0x30))
    tbs = _DER(fields.take(0x30))
    version_2 = tbs.next_is(0x02)
    if version_2 and tbs.take(0x02) != b'\x01':
        raise ValueError('expected CRL v2 or omitted v1 version')
    _check_x509_signature(tbs, fields)
    tbs.take(0x30)  # Issuer.
    _check_x509_time(tbs)  # thisUpdate.
    if not tbs.next_is(0x17) and not tbs.next_is(0x18):
        raise ValueError('missing CRL nextUpdate')
    _check_x509_time(tbs)  # nextUpdate.
    if tbs.next_is(0x30):
        revoked = _DER(tbs.take(0x30))
        while revoked.position < len(revoked.data):
            entry = _DER(revoked.take(0x30))
            entry.take(0x02)  # userCertificate.
            entry.take(0x17 if entry.next_is(0x17) else 0x18)  # revocationDate.
            if entry.next_is(0x30):
                if not version_2:
                    raise ValueError('revoked certificate extensions require CRL v2')
                _check_extensions(entry.take_encoded(0x30))
            entry.done()
    if tbs.next_is(0xa0):
        if not version_2:
            raise ValueError('CRL extensions require v2')
        _check_extensions(tbs.take(0xa0))
    tbs.done()
    crl = load_der_x509_crl(encoded)
    if not crl.issuer.rdns:
        raise ValueError('empty CRL issuer Name')
    try:
        crl.extensions
        for entry in crl:
            entry.extensions
    except UnsupportedGeneralNameType as error:
        raise ValueError(f'invalid X.509 revocation extension: {error}') from error


def _check_optional_set(fields, tag, field_name, parse_member, *, nonempty=False):
    if not fields.next_is(tag):
        return
    try:
        content = fields.take(tag)
        if nonempty and not content:
            raise ValueError('empty DER SET OF')
        for member in _set_members(content, 0x30):
            parse_member(member)
    except MissingAttributeSchema:
        raise
    except ValueError as error:
        raise ValueError(f'invalid SignedData {field_name}: {error}') from error


def _signed_data(envelope):
    outer = _DER(envelope)
    content_info = _DER(outer.take(0x30))
    outer.done()
    if content_info.take(0x06) != _SIGNED_DATA:
        raise ValueError('expected SM2 SignedData content type')
    tagged = _DER(content_info.take(0xa0))
    content_info.done()
    signed_data = _DER(tagged.take(0x30))
    tagged.done()
    if signed_data.take(0x02) != b'\x01':
        raise ValueError('unsupported SignedData version')
    return signed_data


def _content(fields):
    encapsulated = _DER(fields.take(0x30))
    oid = encapsulated.take(0x06)
    _check_oid(oid)
    content = None
    if encapsulated.next_is(0xa0):
        attached = _DER(encapsulated.take(0xa0))
        content = attached.take(0x04)
        attached.done()
    encapsulated.done()
    return oid, content


def _signer_infos(fields):
    _check_optional_set(fields, 0xa0, 'certificates', _check_certificate)
    _check_optional_set(fields, 0xa1, 'crls', _check_crl)
    signers = fields.take(0x31)
    fields.done()
    return signers


def _signer_identifier(signer):
    if signer.take(0x02) != b'\x02':
        raise ValueError('expected SignerInfo version 2')
    return signer.take_encoded(0x30)


def _signer_signature(signer, attribute_schemas=None):
    _algorithm(signer, _SM2_SIGNATURE)
    signature = _signature(signer.take(0x04))
    _check_optional_set(signer, 0xa1, 'unsignedAttrs',
                        lambda member: _attribute(member, attribute_schemas), nonempty=True)
    signer.done()
    return signature


def _direct_signature(envelope, message, signer_identifier):
    fields = _signed_data(envelope)
    algorithms = _DER(fields.take(0x31))
    _digest_algorithm(algorithms)
    algorithms.done()
    oid, content = _content(fields)
    if oid != _DATA:
        raise ValueError('expected SM2 data content type')
    if content is not None and content != message:
        raise ValueError('SignedData content differs from the approved transaction message')

    signers = _DER(_signer_infos(fields))
    signer = _DER(signers.take(0x30))
    signers.done()
    if _signer_identifier(signer) != signer_identifier:
        raise ValueError('SignedData signer identifier differs from the configured signer')
    _digest_algorithm(signer)
    if signer.next_is(0xa0):
        raise ValueError('signedAttrs signatures cannot authorize the existing payment template')
    return _signer_signature(signer)


def _signed_attribute_payload(encoded, content_digest, attribute_schemas=None):
    members = _DER(encoded).take(0xa0)
    digests = []
    for member in _set_members(members, 0x30):
        oid, values = _attribute(member, attribute_schemas)
        if oid == _MESSAGE_DIGEST:
            digests.append(values)
    if len(digests) != 1 or len(digests[0]) != 1:
        raise ValueError('signedAttrs requires exactly one messageDigest with one value')
    value = _DER(digests[0][0])
    if value.take(0x04) != content_digest:
        raise ValueError('signedAttrs messageDigest differs from SM3 of the content')
    value.done()
    # The signing input is the DER encoding of the SignedAttributes SET OF.
    return b'\x31' + encoded[1:]


def verify_signed_data(envelope, trusted_signers, *, detached_content=None, attribute_schemas=None):
    """Verify one or more v2 signers and return the signed content octets.

    trusted_signers maps DER IssuerAndSerialNumber to (SM2 public key, user ID).
    Use externally authenticated keys. Certificate path and revocation
    decisions belong to the caller. Raises ValueError on a rejected envelope.
    Supply attribute_schemas as a mapping from dotted attribute OIDs to
    asn1crypto ASN.1 classes for schema-aware DER checks. Missing types in
    this mode raise MissingAttributeSchema. messageDigest has a built-in type.
    """
    if not isinstance(envelope, bytes):
        raise ValueError('expected a DER SignedData envelope')
    if detached_content is not None and not isinstance(detached_content, bytes):
        raise ValueError('expected detached content octets')

    fields = _signed_data(envelope)
    algorithms = fields.take(0x31)
    if not algorithms:
        raise ValueError('expected SM3 in digestAlgorithms')
    for algorithm in _set_members(algorithms, 0x30):
        _digest_algorithm(_DER(algorithm))
    _, content = _content(fields)
    if content is None:
        if detached_content is None:
            raise ValueError('SignedData requires detached content')
        content = detached_content
    elif detached_content is not None and detached_content != content:
        raise ValueError('supplied content differs from encapsulated SignedData content')

    signers = _signer_infos(fields)
    if not signers:
        raise ValueError('SignedData requires at least one signer')
    content_digest = sm3(content)
    for encoded in _set_members(signers, 0x30):
        signer = _DER(_DER(encoded).take(0x30))
        identifier = _signer_identifier(signer)
        _check_issuer_and_serial_number(identifier)
        if identifier not in trusted_signers:
            raise ValueError('untrusted SignedData signer identifier')
        key, user_id = trusted_signers[identifier]
        _digest_algorithm(signer)
        payload = content
        if signer.next_is(0xa0):
            payload = _signed_attribute_payload(signer.take_encoded(0xa0), content_digest, attribute_schemas)
        signature = _signer_signature(signer, attribute_schemas)
        if not verify(key, payload, signature, user_id):
            raise ValueError('invalid SignedData signature')
    return content


def signed_data_signer(signer, key, *, signer_identifier):
    """Adapt signer(message, user_id) returning SignedData to the wallet API.

    Pin the complete DER IssuerAndSerialNumber from trusted signer configuration.
    Require SignedData version 1 and SignerInfo version 2 for every response.
    """
    parse_public(key)
    if not isinstance(signer_identifier, bytes):
        raise ValueError('expected a pinned DER IssuerAndSerialNumber')
    _check_issuer_and_serial_number(signer_identifier)

    def sign(message, user_id):
        if not isinstance(message, bytes) or len(message) != 32 or user_id != USER_ID:
            raise ValueError('expected the template transaction message and SM2 user ID')
        envelope = signer(message, user_id)
        if not isinstance(envelope, bytes):
            raise ValueError('expected a DER SignedData response')
        signature = _direct_signature(envelope, message, signer_identifier)
        if not verify(key, message, signature, user_id):
            raise ValueError('SignedData does not authorize the approved transaction message')
        return signature

    return sign
