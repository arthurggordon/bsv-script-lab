"""Public, deterministic TEST ONLY fixtures; never fund these keys."""
from hashlib import sha256
from dataclasses import replace
from lamport import public_key, sign_digest
from script import locking_script
from shared.transaction import Transaction, Input, Output, preimage_all, hash256
from shared.script import push


def test_secret(label=b'fixture-v1'):
    return b''.join(sha256(b'BSV-Script-Lab/Lamport/TEST-ONLY/'+label+i.to_bytes(2,'big')).digest() for i in range(512))


def fixture():
    secret = test_secret()
    key = public_key(secret)
    lock = locking_script(key)
    parent = Transaction((Input(b'\x22'*32, 0),), (Output(10000, lock),))
    tx = Transaction((Input(parent.txid_wire(), 0),), (Output(9900, b'\x51'),))
    pre = preimage_all(tx, 0, 10000)
    sig = sign_digest(secret, hash256(pre))
    return secret, key, lock, parent, tx, pre, sig


def cases():
    """Each case is (label, transaction, parent-per-input, input-index, expected)."""
    secret, key, lock, parent, tx, pre, sig = fixture()
    unlock = push(pre)+push(sig)
    signed = tx.with_script(0, unlock)
    yield 'valid', signed, [parent], 0, True
    changes = {
        'output_amount': replace(tx, outputs=(Output(9899,b'\x51'),)),
        'output_script': replace(tx, outputs=(Output(9900,b'\x00'),)),
        'locktime': replace(tx, locktime=1),
        'version': replace(tx, version=1),
        'sequence': replace(tx, inputs=(replace(tx.inputs[0],sequence=1),)),
        'outpoint_index': replace(tx, inputs=(replace(tx.inputs[0],vout=1),)),
        'outpoint_hash': replace(tx, inputs=(replace(tx.inputs[0],txid=b'\x33'*32),)),
    }
    for label, changed in changes.items():
        # Use real previous script/value even when the outpoint is deliberately wrong.
        yield label, changed.with_script(0,unlock), [parent], 0, False
        fake = preimage_all(changed,0,10000)
        yield 'supplied_'+label, tx.with_script(0,push(fake)+push(sign_digest(secret,hash256(fake)))), [parent], 0, False
    for label, bad in [('short_pre',pre[:-1]),('long_pre',pre+b'\0'),('wrong_flag',pre[:-4]+b'\x42\0\0\0'),
                       ('wrong_script_code',pre[:105]+b'\xad'+pre[106:]),
                       ('wrong_amount',preimage_all(tx,0,10001))]:
        yield label, tx.with_script(0,push(bad)+push(sign_digest(secret,hash256(bad)))), [parent], 0, False
    for label, bad in [('short_sig',sig[:-1]),('long_sig',sig+b'\0'),('wrong_sig',bytes([sig[0]^1])+sig[1:]),
                       ('swapped_blocks',sig[32:64]+sig[:32]+sig[64:]),
                       ('wrong_key',sign_digest(test_secret(b'other'),hash256(pre))),
                       ('wrong_digest',sign_digest(secret,sha256(b'wrong').digest()))]:
        yield label, tx.with_script(0,push(pre)+push(bad)), [parent], 0, False
    yield 'extra_item', tx.with_script(0,push(b'extra')+unlock), [parent], 0, False
    yield 'missing_item', tx.with_script(0,push(sig)), [parent], 0, False
    other = Transaction((Input(b'\x44'*32,0),),(Output(1000,b'\x51'),))
    multi = Transaction((Input(other.txid_wire(),0),Input(parent.txid_wire(),0)),(Output(500,b'\x51'),Output(10400,b'\x51')))
    p = preimage_all(multi,1,10000)
    multi = multi.with_script(1,push(p)+push(sign_digest(secret,hash256(p))))
    yield 'multi_input',multi,[other,parent],1,True
    yield 'output_order',replace(multi,outputs=tuple(reversed(multi.outputs))),[other,parent],1,False
    yield 'other_sequence',replace(multi,inputs=(replace(multi.inputs[0],sequence=1),multi.inputs[1])),[other,parent],1,False
    yield 'other_outpoint',replace(multi,inputs=(replace(multi.inputs[0],txid=b'\x77'*32),multi.inputs[1])),[other,parent],1,False
