"""Signing messages for v2. Only the effective input coverage enters the signature."""
from dataclasses import dataclass
from shared.transaction import amount, blob, compact, hash256, preimage_all

ALL, NONE, SINGLE = 1, 2, 3
CHRONICLE, FORKID, ANYONECANPAY = 0x20, 0x40, 0x80
SUPPORTED_TYPES = frozenset(
    FORKID | algorithm | inputs | base
    for algorithm in (0, CHRONICLE)
    for inputs in (0, ANYONECANPAY)
    for base in (ALL, NONE, SINGLE)
)
ORDINARY_CODE = bytes.fromhex('ac')
COMPANION_CODE = bytes.fromhex('ad68abac')
ZERO_HASH = bytes(32)
NULL_OUTPUT = bytes.fromhex('ffffffffffffffff00')


def u32(value):
    return value.to_bytes(4, 'little')


def bip143(tx, index, previous_amount, flag, code):
    if flag == 0x41:
        return preimage_all(tx, index, previous_amount, code)
    base = flag & 0x1f
    anyone = bool(flag & ANYONECANPAY)
    current = tx.inputs[index]
    prevouts = ZERO_HASH if anyone else hash256(b''.join(x.outpoint() for x in tx.inputs))
    sequences = ZERO_HASH
    if not anyone and base == ALL:
        sequences = hash256(b''.join(u32(x.sequence) for x in tx.inputs))
    outputs = ZERO_HASH
    if base == ALL:
        outputs = hash256(b''.join(x.serialize() for x in tx.outputs))
    elif base == SINGLE and index < len(tx.outputs):
        outputs = hash256(tx.outputs[index].serialize())
    return b''.join((u32(tx.version), prevouts, sequences, current.outpoint(), blob(code),
                     amount(previous_amount), u32(current.sequence), outputs, u32(tx.locktime), u32(flag)))


def otda(tx, index, flag):
    # All ordinary OTDA checks execute after the final separator (scriptCode = ac).
    base = flag & 0x1f
    indices = (index,) if flag & ANYONECANPAY else range(len(tx.inputs))
    pieces = [u32(tx.version), compact(len(indices))]
    for i in indices:
        txin = tx.inputs[i]
        sequence = txin.sequence if i == index or base == ALL else 0
        pieces.extend((txin.outpoint(), blob(ORDINARY_CODE if i == index else b''), u32(sequence)))
    if base == ALL:
        pieces.append(compact(len(tx.outputs)))
        pieces.extend(out.serialize() for out in tx.outputs)
    elif base == SINGLE:
        if index >= len(tx.outputs):
            raise ValueError('unpaired OTDA SINGLE has no native signing preimage')
        pieces.extend((compact(index + 1), NULL_OUTPUT * index, tx.outputs[index].serialize()))
    else:
        pieces.append(compact(0))
    pieces.extend((u32(tx.locktime), u32(flag)))
    return b''.join(pieces)


@dataclass(frozen=True)
class Authorization:
    requested_type: int
    preimage: bytes
    companion: bool

    @property
    def message(self):
        return hash256(self.preimage)


def authorization(tx, index, previous_amount, sighash_type=0x41, *, chronicle_active=True):
    """Generate the message and witness P. Set chronicle_active from the spend context."""
    if type(sighash_type) is not int or sighash_type not in SUPPORTED_TYPES:
        raise ValueError('unsupported ForkID sighash type')
    if not 0 <= index < len(tx.inputs):
        raise ValueError('invalid input index')
    if sighash_type & CHRONICLE and not chronicle_active:
        raise ValueError('Chronicle sighash is disabled in this spend context')
    if sighash_type & CHRONICLE:
        if (sighash_type & 0x1f) == SINGLE and index >= len(tx.outputs):
            pre = bip143(tx, index, previous_amount, sighash_type ^ CHRONICLE, COMPANION_CODE)
            return Authorization(sighash_type, pre, True)
        return Authorization(sighash_type, otda(tx, index, sighash_type), False)
    return Authorization(sighash_type, bip143(tx, index, previous_amount, sighash_type, ORDINARY_CODE), False)
