"""OpenSSL path validation against a caller-selected trust anchor."""

from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import InvalidVersion, load_der_x509_certificate


def _load_certificate(encoded, role):
    if not isinstance(encoded, bytes):
        raise ValueError(f'expected a DER {role} certificate')
    try:
        return load_der_x509_certificate(encoded)
    except InvalidVersion as error:
        # GB/T 20518 permits v2, but this loader and the revocation logic
        # built on it accept only v1 and v3. Fail closed with the API's type.
        raise ValueError(f'unsupported {role} certificate version: {error}') from error
    except ValueError as error:
        raise ValueError(f'invalid DER {role} certificate') from error


def _validity_error(certificate, when):
    if when < certificate.not_valid_before_utc:
        return 'certificate is not yet valid'
    if when > certificate.not_valid_after_utc:
        return 'certificate has expired'
    return None


def _require_validity(certificate, role, when):
    error = _validity_error(certificate, when)
    if error is not None:
        raise ValueError(f'{role} certificate path validation failed: {error}')


def _openssl(command, workspace, *, data=None):
    try:
        return subprocess.run(command, cwd=workspace, input=data, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError('OpenSSL certificate path validation could not run') from error


def _openssl_subject(pem, workspace):
    result = _openssl(['openssl', 'x509', '-noout', '-subject', '-nameopt', 'RFC2253'], workspace, data=pem)
    subject = result.stdout.rstrip(b'\r\n')
    if result.returncode != 0 or not subject.startswith(b'subject=') or b'\n' in subject:
        raise ValueError('OpenSSL could not identify a certificate path subject')
    return subject.removeprefix(b'subject=')


def _selected_path(stdout, candidate, trust_anchor, subjects, intermediates):
    marker = b' (untrusted)'
    rows = re.findall(rb'^depth=([0-9]+): (.*)$', stdout, re.MULTILINE)
    if (not rows or [int(depth) for depth, _ in rows] != list(range(len(rows)))
            or rows[-1][1] != subjects[trust_anchor]):
        raise ValueError('OpenSSL could not identify the selected certificate path to the trust anchor')
    if len(rows) == 1:
        if candidate != trust_anchor:
            raise ValueError('OpenSSL selected a different certificate as the target trust anchor')
        return (trust_anchor,)
    if rows[0][1] != subjects[candidate] + marker:
        raise ValueError('OpenSSL could not identify the selected path target')
    chain = [candidate]
    for _, label in rows[1:-1]:
        matches = [cert for cert in intermediates if subjects[cert] + marker == label]
        if len(matches) != 1 or matches[0] in chain or matches[0] == trust_anchor:
            raise ValueError('selected certificate path has an ambiguous intermediate subject')
        chain.append(matches[0])
    return (*chain, trust_anchor)


def verify_revocation_paths(target, signers, *, trust_anchor, intermediates, validation_time, identify=False):
    """Validate paths under one anchor and optionally return the selected DER chains."""
    anchor = _load_certificate(trust_anchor, 'trust anchor')
    _require_validity(anchor, 'trust anchor', validation_time)
    anchor_pem = anchor.public_bytes(Encoding.PEM)
    untrusted = {}
    for encoded in intermediates:
        certificate = _load_certificate(encoded, 'intermediate')
        if _validity_error(certificate, validation_time) is None:
            untrusted[encoded] = certificate.public_bytes(Encoding.PEM)
    untrusted_pem = b''.join(untrusted.values())
    with TemporaryDirectory(prefix='bsv-x509-revocation-path-') as directory:
        workspace = Path(directory)
        (workspace / 'anchor.pem').write_bytes(anchor_pem)
        # The default PKIX initial policy set is anyPolicy, including when
        # an intermediate requires an explicit policy later in the path.
        # Every supplied path candidate is time-checked here with inclusive
        # endpoints. OpenSSL's -attime would exclude the notAfter instant.
        command = ['openssl', 'verify', '-no-CAfile', '-no-CApath', '-no-CAstore',
                   '-trusted', 'anchor.pem', '-partial_chain', '-x509_strict', '-policy_check',
                   '-policy', '2.5.29.32.0', '-no_check_time']
        if untrusted_pem:
            (workspace / 'intermediates.pem').write_bytes(untrusted_pem)
            command += ['-untrusted', 'intermediates.pem']
        certificates = [(target, 'target', 'any')]
        certificates += [(cert, 'CRL signer', 'crlsign') for cert in signers]
        if identify:
            command += ['-show_chain', '-nameopt', 'RFC2253']
            subjects = {encoded: _openssl_subject(pem, workspace)
                        for encoded, pem in {trust_anchor: anchor_pem, **untrusted}.items()}
        selected = {}
        for encoded, role, purpose in certificates:
            certificate = _load_certificate(encoded, role)
            _require_validity(certificate, role, validation_time)
            pem = certificate.public_bytes(Encoding.PEM)
            (workspace / 'candidate.pem').write_bytes(pem)
            result = _openssl([*command, '-purpose', purpose, 'candidate.pem'], workspace)
            if result.returncode != 0:
                detail = ' '.join(result.stderr.decode(errors='replace').split())
                raise ValueError(f'{role} certificate path validation failed: {detail}')
            if identify:
                if encoded not in subjects:
                    subjects[encoded] = _openssl_subject(pem, workspace)
                chain = _selected_path(result.stdout, encoded, trust_anchor, subjects, untrusted)
                if encoded in selected and selected[encoded] != chain:
                    raise ValueError('OpenSSL selected different target and CRL signer paths for the same certificate')
                selected[encoded] = chain
        return selected if identify else None
