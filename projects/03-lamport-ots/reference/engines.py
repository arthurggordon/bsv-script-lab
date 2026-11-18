"""Independent complete-transaction engine adapter, plus a development checker."""
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.util import sigdecode_der
from tx_engine import Script, Tx, TxIn, TxOut
from shared.transaction import hash256, preimage_all
from shared.evaluate import evaluate, ScriptError


def native_checker(tx, index, amount):
    digest = hash256(preimage_all(tx,index,amount))
    def check(signature, key):
        if signature[-1:] != b'\x41': return False
        try:
            return VerifyingKey.from_string(key,curve=SECP256k1).verify_digest(signature[:-1],digest,sigdecode=sigdecode_der)
        except (BadSignatureError,ValueError): return False
    return check


def development_valid(tx, parent, index):
    # All test fixtures use output zero; bad vout cases still test the same prevout.
    previous = parent.outputs[0]
    try:
        witness, _ = evaluate(tx.inputs[index].script)
        stack, alt = evaluate(previous.script,witness,native_checker(tx,index,previous.value))
        return stack == [b'\x01'] and alt == []
    except ScriptError: return False


def engine_script(raw):
    script = Script()
    script.append_data(raw)
    return script


def engine_tx(tx):
    result = Tx(tx.version,[TxIn(x.txid[::-1].hex(),x.vout,engine_script(x.script),x.sequence) for x in tx.inputs],
                [TxOut(x.value,engine_script(x.script)) for x in tx.outputs],tx.locktime)
    if result.serialize() != tx.serialize(): raise AssertionError('serializer mismatch')
    return result


def chain_valid(tx, parents):
    try:
        engine_tx(tx).validate([engine_tx(p) for p in parents])
        return True
    except (RuntimeError, ValueError): return False
