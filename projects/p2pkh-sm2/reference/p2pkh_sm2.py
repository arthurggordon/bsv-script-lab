"""Construct, recognize, and authorize canonical P2PKH-SM2 v1 payments."""
from functools import cache
from hashlib import sha256
import json
from pathlib import Path
from assemble import assemble
from sm2 import USER_ID,hash256,public_key_hash160,verify
from shared.script import push
from shared.transaction import Transaction,Input,Output,preimage_all,amount

MANIFEST=Path(__file__).resolve().parents[1]/'template/layout.json'


@cache
def _canonical():
    layout=json.loads(MANIFEST.read_text())
    raw=assemble(bytes(20))
    if len(raw)!=layout['script_bytes'] or sha256(raw).hexdigest()!=layout['base_script_sha256']:
        raise ValueError('canonical SM2 template differs from manifest')
    start=layout['owner_hash160']['offset']
    if raw[start:start+20]!=bytes(20) or sha256(raw[:start]+raw[start+20:]).hexdigest()!=layout['fixed_bytes_sha256']:
        raise ValueError('invalid SM2 owner slot/fingerprint')
    return raw,start


def locking_script_from_owner_hash(owner):
    if not isinstance(owner,bytes) or len(owner)!=20: raise ValueError('expected a 20-byte owner hash')
    raw,start=_canonical()
    return raw[:start]+owner+raw[start+20:]


def locking_script_from_public_key(key): return locking_script_from_owner_hash(public_key_hash160(key))


def recognize(raw):
    if not isinstance(raw,bytes): return None
    template,start=_canonical()
    if len(raw)!=len(template) or raw[:start]!=template[:start] or raw[start+20:]!=template[start+20:]: return None
    return raw[start:start+20]


def current_input_unlock(tx,index,previous_amount,key,signature):
    public_key_hash160(key)
    preimage=preimage_all(tx,index,previous_amount)
    message=hash256(preimage)
    k1_n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    k1_gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    if (int.from_bytes(message,'big')+k1_gx)%k1_n==0:
        raise ValueError('degenerate PUSHTX digest; rebuild the transaction')
    if not verify(key,message,signature): raise ValueError('invalid SM2 authorization')
    return push(preimage)+push(key)+push(signature)


def sign_payment(funding_raw,vout,outputs,fee,key,signer):
    """One-input payment. signer(message, user_id) returns 64-byte r||s.

    message is SHA256d(P), NOT the SM2 prehash. A normal SM2 message-sign API
    computes ZA and SM3 itself. The caller authenticates the funding transaction
    and presents destinations/change/fee to the key holder before this call.
    """
    funding=Transaction.parse(funding_raw)
    if not 0<=vout<len(funding.outputs): raise ValueError('invalid funding output')
    previous=funding.outputs[vout]
    owner=public_key_hash160(key)
    if recognize(previous.script)!=owner: raise ValueError('funding output does not belong to key/template')
    amount(fee); outputs=tuple(outputs)
    if not outputs: raise ValueError('payment requires outputs')
    for out in outputs: out.serialize()
    if sum(x.value for x in outputs)+fee!=previous.value: raise ValueError('outputs and fee must equal input value')
    tx=Transaction((Input(funding.txid_wire(),vout),),outputs)
    message=hash256(preimage_all(tx,0,previous.value))
    signature=signer(message,USER_ID)
    return tx.with_script(0,current_input_unlock(tx,0,previous.value,key,signature))
