"""Create and recognize deferred P-256 payment outputs, and prepare activation inputs."""
from dataclasses import dataclass
from functools import cache
from hashlib import sha256
from pathlib import Path
import sys

from shared.script import OPS, assemble, push
from shared.transaction import FORKID, SIGHASH_SINGLE, Output, Transaction, amount, hash256, preimage_forkid

R1_REFERENCE = Path(__file__).resolve().parents[2] / 'p2pkh-r1/reference'
sys.path.append(str(R1_REFERENCE))
from p2pkh_r1 import locking_script_from_public_key


VERSION_TAG = b'R1DEFER\x01'
PUBLIC_KEY_SIZE = 65
SCRIPT_CODE = bytes([OPS['OP_CHECKSIG']])
ACTIVATION_SIGHASH = FORKID | SIGHASH_SINGLE
ASM = Path(__file__).with_name('asm')


@dataclass(frozen=True)
class Commitment:
    public_key: bytes
    script_hash: bytes
    output_hash: bytes


def target_output(value: int, public_key: bytes) -> Output:
    """Return the canonical P2PKH-R1 destination at the full input value."""
    amount(value)
    return Output(value, locking_script_from_public_key(public_key))


@cache
def _binder_blocks() -> dict[str, bytes]:
    return {
        name: assemble(R1_REFERENCE / 'asm', bytes(20), entry=name)
        for name in ('UINT256BE', 'K1_BIND_DIGEST')
    }


def _locking_script(value: int, commitment: Commitment) -> bytes:
    return assemble(ASM, bytes(20), injected={
        **_binder_blocks(),
        'HEADER': push(VERSION_TAG) + push(commitment.public_key) + push(commitment.script_hash),
        'VALUE': push(amount(value)),
        'TARGET_HASH': push(commitment.output_hash),
    })


def _commitment(public_key: bytes, target: Output) -> Commitment:
    output_hash = hash256(target.serialize())
    if output_hash == bytes(32):
        raise ValueError('zero target commitment')
    return Commitment(public_key, sha256(target.script).digest(), output_hash)


def funding_output(value: int, public_key: bytes) -> Output:
    """Construct a short output from the full uncompressed P-256 public key."""
    commitment = _commitment(public_key, target_output(value, public_key))
    return Output(value, _locking_script(value, commitment))


def recognize(output: Output, *, expected_key: bytes | None = None) -> Commitment | None:
    """Recognize only an exact canonical output, including both commitments and its value."""
    prefix = push(VERSION_TAG) + bytes([PUBLIC_KEY_SIZE])
    if not output.script.startswith(prefix):
        return None
    public_key = output.script[len(prefix):len(prefix) + PUBLIC_KEY_SIZE]
    if expected_key is not None and expected_key != public_key:
        return None
    try:
        commitment = _commitment(public_key, target_output(output.value, public_key))
    except ValueError:
        return None
    return commitment if output.script == _locking_script(output.value, commitment) else None


def activate_input(tx: Transaction, index: int, funding_raw: bytes) -> Transaction:
    """Prepare one activation input in an already assembled transaction, without a private key."""
    if not 0 <= index < len(tx.inputs) or index >= len(tx.outputs):
        raise ValueError('activation needs a same-index output')
    current = tx.inputs[index]
    if current.script:
        raise ValueError('activation input already has an unlocking script')
    funding = Transaction.parse(funding_raw)
    if current.txid != funding.txid_wire() or not 0 <= current.vout < len(funding.outputs):
        raise ValueError('funding outpoint mismatch')
    previous = funding.outputs[current.vout]
    commitment = recognize(previous)
    if commitment is None:
        raise ValueError('funding output is not a canonical deferred lock')
    if hash256(tx.outputs[index].serialize()) != commitment.output_hash:
        raise ValueError('activation output does not match the committed value and R1 script')
    preimage = preimage_forkid(tx, index, previous.value, SCRIPT_CODE, ACTIVATION_SIGHASH)
    return tx.with_script(index, push(preimage))
