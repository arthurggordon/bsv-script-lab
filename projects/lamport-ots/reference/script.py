"""Unrolled Lamport verifier and fixed-r PUSHTX transaction binding."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from shared.script import asm, push, number
from lamport import KEY_BYTES, require_bytes
from shared.transaction import SIGHASH_TYPES

N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
R = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
PUBLIC = bytes.fromhex('02' + f'{R:064x}')
REVERSE32 = asm('OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK')*31 + asm('OP_FROMALTSTACK OP_CAT')*31


def _binding_der():
    # H -> positive big-endian integer -> s=min((H+r)%n,n-(H+r)%n).
    # Construct strict DER in Script; no supplied ECDSA signature is trusted.
    return (REVERSE32 + push(b'\0') + asm('OP_CAT OP_BIN2NUM') + number(R) + asm('OP_ADD') +
            number(N) + asm('OP_MOD OP_DUP OP_VERIFY OP_DUP') + number(N) +
            asm('OP_SWAP OP_SUB OP_MIN OP_SIZE OP_TOALTSTACK') + number(32) + asm('OP_NUM2BIN') +
            REVERSE32 + number(32) + asm('OP_FROMALTSTACK OP_SUB OP_SPLIT OP_NIP OP_SIZE OP_TUCK OP_TOALTSTACK OP_CAT') +
            push(bytes.fromhex('0220'+f'{R:064x}'+'02')) + asm('OP_SWAP OP_CAT OP_FROMALTSTACK') + number(36) +
            asm('OP_ADD') + push(b'\x30') + asm('OP_SWAP OP_CAT OP_SWAP OP_CAT'))


def binding():
    return _binding_der() + push(b'\x41') + asm('OP_CAT') + push(PUBLIC) + asm('OP_CODESEPARATOR OP_CHECKSIG')


def verifier(key):
    """Input S,H; output empty stack. Retains any earlier altstack entries."""
    require_bytes(key, KEY_BYTES, 'public key')
    code = bytearray()
    for byte in range(32):
        code += asm('OP_1 OP_SPLIT OP_SWAP') + push(b'\0') + asm('OP_CAT OP_BIN2NUM OP_SWAP OP_TOALTSTACK')
        for bit in range(8):
            i = byte*8 + bit
            p0, p1 = key[64*i:64*i+32], key[64*i+32:64*i+64]
            code += asm('OP_DUP OP_2 OP_MOD OP_IF') + push(p1) + asm('OP_ELSE') + push(p0)
            code += asm('OP_ENDIF OP_TOALTSTACK OP_2 OP_DIV OP_SWAP') + number(32)
            code += asm('OP_SPLIT OP_SWAP OP_SHA256 OP_FROMALTSTACK OP_EQUALVERIFY OP_SWAP')
        code += asm('OP_DROP OP_FROMALTSTACK')
    return bytes(code) + asm('OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY')


def _v1_script(key, *, transaction=True):
    """Witness: [158-byte ForkID ALL preimage OR 32-byte digest, 8192-byte signature]."""
    code = asm('OP_DEPTH OP_2 OP_NUMEQUALVERIFY OP_OVER OP_SIZE')
    code += number(158 if transaction else 32) + asm('OP_NUMEQUALVERIFY OP_DROP OP_SIZE')
    code += number(8192) + asm('OP_NUMEQUALVERIFY')
    if transaction:
        code += asm('OP_OVER') + number(104) + asm('OP_SPLIT OP_NIP OP_2 OP_SPLIT OP_DROP') + push(b'\x01\xac') + asm('OP_EQUALVERIFY')
        code += asm('OP_OVER') + number(154) + asm('OP_SPLIT OP_NIP') + push(b'\x41\0\0\0') + asm('OP_EQUALVERIFY OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    else:
        code += asm('OP_SWAP')
    code += verifier(key)
    return code + (asm('OP_FROMALTSTACK') + binding() if transaction else asm('OP_1'))


# Keep these suffixes in sync with the final branch in _universal_binding.
ORDINARY_CODE = asm('OP_ENDIF OP_CHECKSIG')
COMPANION_CODE = asm('OP_IF OP_CHECKSIGVERIFY OP_ELSE OP_CODESEPARATOR OP_ENDIF OP_CHECKSIG')
# Fixed (d=k=1) signature of the native OTDA unpaired SINGLE constant,
# read as big-endian ECDSA digest 01 00...00 (not integer 1).
ONE_DER = bytes.fromhex('30440220' + f'{R:064x}' + '0220' + f'{R+(1<<248):064x}')


def legacy_locking_script(key):
    """The original two-push ForkID ALL template, preserved byte-for-byte."""
    return _v1_script(key)


def _check_bip143_shape(length, script_code):
    return (asm('OP_OVER OP_SIZE') + number(length) + asm('OP_NUMEQUALVERIFY') +
            number(104) + asm('OP_SPLIT OP_NIP') + number(len(script_code)+1) +
            asm('OP_SPLIT OP_DROP') + push(bytes([len(script_code)])+script_code) + asm('OP_EQUALVERIFY'))


def _check_authorization():
    # Entry P S mode; alt: mode, then actual base binding's one-byte type.
    code = asm('OP_DEPTH OP_3 OP_NUMEQUALVERIFY OP_DUP OP_0 OP_EQUAL OP_OVER OP_1 OP_EQUAL OP_BOOLOR OP_VERIFY')
    code += asm('OP_DUP OP_TOALTSTACK')
    code += asm('OP_2 OP_PICK OP_SIZE OP_4 OP_SUB OP_SPLIT OP_NIP')
    # Check trailing three bytes are zero and validate the exact one-byte type.
    code += asm('OP_1 OP_SPLIT') + push(bytes(3)) + asm('OP_EQUALVERIFY OP_DUP')
    for i, flag in enumerate(sorted(SIGHASH_TYPES)):
        code += (asm('OP_OVER') if i else b'') + push(bytes([flag])) + asm('OP_EQUAL')
        if i:
            code += asm('OP_BOOLOR')
    code += asm('OP_VERIFY OP_TOALTSTACK OP_IF')
    # Reuse the authenticated type via altstack; only 0x43/c3 may take the companion branch.
    code += asm('OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_DUP') + push(b'\x43') + asm('OP_EQUAL OP_SWAP')
    code += push(b'\xc3') + asm('OP_EQUAL OP_BOOLOR OP_VERIFY')
    code += _check_bip143_shape(163, COMPANION_CODE)
    code += asm('OP_OVER') + number(123) + asm('OP_SPLIT OP_NIP') + number(32) + asm('OP_SPLIT OP_DROP')
    code += push(bytes(32)) + asm('OP_EQUALVERIFY OP_ELSE')
    code += asm('OP_FROMALTSTACK OP_DUP OP_TOALTSTACK') + push(b'\x20') + asm('OP_AND')
    code += push(b'\x20') + asm('OP_EQUAL OP_NOTIF') + _check_bip143_shape(159, ORDINARY_CODE)
    return code + asm('OP_ENDIF OP_ENDIF')


def _universal_binding():
    # Entry H; alt bottom-to-top mode, type. Both signatures are derived on chain.
    code = _binding_der() + asm('OP_FROMALTSTACK OP_CAT') + push(PUBLIC)
    code += asm('OP_FROMALTSTACK OP_DUP OP_IF OP_TOALTSTACK OP_OVER OP_SIZE OP_1SUB OP_SPLIT OP_NIP')
    code += push(b'\x20') + asm('OP_OR') + push(ONE_DER) + asm('OP_SWAP OP_CAT') + push(PUBLIC)
    code += asm('OP_FROMALTSTACK OP_ENDIF OP_CODESEPARATOR') + COMPANION_CODE
    return code


def locking_script(key, *, transaction=True):
    """Universal lock witness: preimage, packed signature, companion selector."""
    if not transaction:
        return _v1_script(key, transaction=False)
    code = _check_authorization()
    code += asm('OP_SIZE') + number(8192) + asm('OP_NUMEQUALVERIFY OP_SWAP OP_HASH256 OP_DUP OP_TOALTSTACK')
    return code + verifier(key) + asm('OP_FROMALTSTACK') + _universal_binding()
