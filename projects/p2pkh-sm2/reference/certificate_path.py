"""OpenSSL path validation against a caller-selected trust anchor."""

from datetime import datetime, timezone
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate


def _certificate_pem(encoded, role):
    if not isinstance(encoded, bytes):
        raise ValueError(f'expected a DER {role} certificate')
    try:
        return load_der_x509_certificate(encoded).public_bytes(Encoding.PEM)
    except ValueError as error:
        raise ValueError(f'invalid DER {role} certificate') from error


def verify_revocation_paths(target, signers, *, trust_anchor, intermediates, validation_time):
    """Validate target and CRL signer paths with one explicit trusted certificate."""
    elapsed = validation_time - datetime(1970, 1, 1, tzinfo=timezone.utc)
    seconds = elapsed.days * 86400 + elapsed.seconds
    anchor_pem = _certificate_pem(trust_anchor, 'trust anchor')
    untrusted_pem = b''.join(_certificate_pem(cert, 'intermediate') for cert in intermediates)
    with TemporaryDirectory(prefix='bsv-x509-revocation-path-') as directory:
        workspace = Path(directory)
        (workspace / 'anchor.pem').write_bytes(anchor_pem)
        # The default PKIX initial policy set is anyPolicy, including when
        # an intermediate requires an explicit policy later in the path.
        command = ['openssl', 'verify', '-no-CAfile', '-no-CApath', '-no-CAstore',
                   '-trusted', 'anchor.pem', '-partial_chain', '-x509_strict', '-policy_check',
                   '-policy', '2.5.29.32.0', '-attime', str(seconds)]
        if untrusted_pem:
            (workspace / 'intermediates.pem').write_bytes(untrusted_pem)
            command += ['-untrusted', 'intermediates.pem']
        certificates = [(target, 'target', 'any')]
        certificates += [(cert, 'CRL signer', 'crlsign') for cert in signers]
        for encoded, role, purpose in certificates:
            (workspace / 'candidate.pem').write_bytes(_certificate_pem(encoded, role))
            try:
                result = subprocess.run([*command, '-purpose', purpose, 'candidate.pem'],
                                        cwd=workspace, capture_output=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ValueError('OpenSSL certificate path validation could not run') from error
            if result.returncode != 0:
                detail = ' '.join(result.stderr.decode(errors='replace').split())
                raise ValueError(f'{role} certificate path validation failed: {detail}')
