"""One-input payments with an explicitly one-time Lamport signing capability."""
from script import locking_script, N, R
from lamport import verify_digest
from shared.script import push
from shared.transaction import Transaction, Input, amount, preimage_all, hash256


def current_input_unlock(tx, index, previous_amount, key, signature):
    preimage = preimage_all(tx, index, previous_amount)
    digest = hash256(preimage)
    if (int.from_bytes(digest, 'big')+R) % N == 0:
        raise ValueError('degenerate binding digest; rebuild before signing')
    if not verify_digest(key, digest, signature):
        raise ValueError('invalid Lamport signature')
    return push(preimage) + push(signature)


def sign_payment(funding_raw, vout, outputs, fee, signer):
    """Authenticate funding and approve outputs/fee BEFORE calling this API.

    signer must be a fresh OneTimeSigner. Retries, RBF, CPFP designs, backup and
    rollback handling require wallet-level state. Never re-fund the same key.
    """
    funding = Transaction.parse(funding_raw)
    if not 0 <= vout < len(funding.outputs):
        raise ValueError('invalid funding output')
    previous = funding.outputs[vout]
    lock = locking_script(signer.public_key)
    if previous.script != lock:
        raise ValueError('funding output does not match key and canonical template')
    amount(fee)
    outputs = tuple(outputs)
    if not outputs:
        raise ValueError('payment requires outputs')
    for output in outputs:
        output.serialize()
        if output.script in (lock, locking_script(signer.public_key, transaction=False)):
            raise ValueError('change must use a fresh Lamport key')
    if sum(x.value for x in outputs)+fee != previous.value:
        raise ValueError('outputs plus fee must equal input value')
    tx = Transaction((Input(funding.txid_wire(), vout),), outputs)
    digest = hash256(preimage_all(tx, 0, previous.value))
    if (int.from_bytes(digest, 'big')+R) % N == 0:
        raise ValueError('degenerate binding digest; rebuild before signing')
    signature = signer.sign(digest)
    return tx.with_script(0, current_input_unlock(tx, 0, previous.value, signer.public_key, signature))
