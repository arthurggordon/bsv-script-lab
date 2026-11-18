"""Legacy BSV transaction wire format and fixed ForkID ALL preimages."""
from dataclasses import dataclass, replace
from hashlib import sha256


def hash256(b): return sha256(sha256(b).digest()).digest()

def compact(n):
    if not 0<=n<=0xffffffffffffffff: raise ValueError('CompactSize range')
    return bytes([n]) if n<253 else b'\xfd'+n.to_bytes(2,'little') if n<=65535 else b'\xfe'+n.to_bytes(4,'little') if n<=0xffffffff else b'\xff'+n.to_bytes(8,'little')

def blob(b): return compact(len(b))+b

def amount(n):
    if type(n) is not int or not 0<=n<=2_100_000_000_000_000: raise ValueError('invalid satoshi amount')
    return n.to_bytes(8,'little')


@dataclass(frozen=True)
class Input:
    txid: bytes  # 32 bytes in wire (little-endian) order
    vout: int
    script: bytes = b''
    sequence: int = 0xffffffff
    def outpoint(self):
        if len(self.txid)!=32: raise ValueError('txid must have 32 bytes')
        return self.txid+self.vout.to_bytes(4,'little')
    def serialize(self): return self.outpoint()+blob(self.script)+self.sequence.to_bytes(4,'little')


@dataclass(frozen=True)
class Output:
    value: int
    script: bytes
    def serialize(self): return amount(self.value)+blob(self.script)


@dataclass(frozen=True)
class Transaction:
    inputs: tuple[Input,...]
    outputs: tuple[Output,...]
    version: int = 2
    locktime: int = 0
    def serialize(self):
        return self.version.to_bytes(4,'little')+compact(len(self.inputs))+b''.join(x.serialize() for x in self.inputs)+compact(len(self.outputs))+b''.join(x.serialize() for x in self.outputs)+self.locktime.to_bytes(4,'little')
    def txid_wire(self): return hash256(self.serialize())
    def txid(self): return self.txid_wire()[::-1].hex()
    def with_script(self,index,script):
        inputs=list(self.inputs); inputs[index]=replace(inputs[index],script=script)
        return replace(self,inputs=tuple(inputs))
    @classmethod
    def parse(cls,raw):
        cursor=0
        def take(n):
            nonlocal cursor
            if n<0 or cursor+n>len(raw): raise ValueError('truncated transaction')
            result=raw[cursor:cursor+n]; cursor+=n; return result
        def integer(n): return int.from_bytes(take(n),'little')
        def count():
            lead=integer(1)
            if lead<253: return lead
            size={253:2,254:4,255:8}[lead]; value=integer(size)
            if value<({2:253,4:65536,8:4294967296}[size]): raise ValueError('noncanonical CompactSize')
            return value
        version=integer(4)
        inputs=tuple(Input(take(32),integer(4),take(count()),integer(4)) for _ in range(count()))
        outputs=tuple(Output(integer(8),take(count())) for _ in range(count()))
        locktime=integer(4)
        if cursor!=len(raw): raise ValueError('trailing transaction data')
        result=cls(inputs,outputs,version,locktime)
        if result.serialize()!=raw: raise ValueError('noncanonical transaction')
        return result


def preimage_all(tx,index,previous_amount,script_code=b'\xac'):
    if not 0<=index<len(tx.inputs): raise ValueError('invalid input index')
    current=tx.inputs[index]
    return (tx.version.to_bytes(4,'little')+hash256(b''.join(x.outpoint() for x in tx.inputs))+
            hash256(b''.join(x.sequence.to_bytes(4,'little') for x in tx.inputs))+current.outpoint()+
            blob(script_code)+amount(previous_amount)+current.sequence.to_bytes(4,'little')+
            hash256(b''.join(x.serialize() for x in tx.outputs))+tx.locktime.to_bytes(4,'little')+b'\x41\0\0\0')
