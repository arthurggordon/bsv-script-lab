"""Unrolled Lamport verifier and fixed-r PUSHTX transaction binding."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from shared.script import asm, push, number
from lamport import KEY_BYTES, require_bytes

N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
R = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
PUBLIC = bytes.fromhex('02' + f'{R:064x}')
REVERSE32 = asm('OP_1 OP_SPLIT OP_SWAP OP_TOALTSTACK')*31 + asm('OP_FROMALTSTACK OP_CAT')*31


def binding():
    # H -> positive big-endian integer -> s=min((H+r)%n,n-(H+r)%n).
    # Construct strict DER in Script; no supplied ECDSA signature is trusted.
    return (REVERSE32 + push(b'\0') + asm('OP_CAT OP_BIN2NUM') + number(R) + asm('OP_ADD') +
            number(N) + asm('OP_MOD OP_DUP OP_VERIFY OP_DUP') + number(N) +
            asm('OP_SWAP OP_SUB OP_MIN OP_SIZE OP_TOALTSTACK') + number(32) + asm('OP_NUM2BIN') +
            REVERSE32 + number(32) + asm('OP_FROMALTSTACK OP_SUB OP_SPLIT OP_NIP OP_SIZE OP_TUCK OP_TOALTSTACK OP_CAT') +
            push(bytes.fromhex('0220'+f'{R:064x}'+'02')) + asm('OP_SWAP OP_CAT OP_FROMALTSTACK') + number(36) +
            asm('OP_ADD') + push(b'\x30') + asm('OP_SWAP OP_CAT OP_SWAP OP_CAT') + push(b'\x41') +
            asm('OP_CAT') + push(PUBLIC) + asm('OP_CODESEPARATOR OP_CHECKSIG'))


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


def locking_script(key, *, transaction=True):
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
