"""Research local pipe framing; no authentication/network or durable-state claim.

Payloads may contain the issuer response z. Never log a frame or its repr.
"""
import json

MAGIC=b'NCLI\0\1'
CAP=512<<10


def _exact(reader,n):
    out=bytearray()
    while len(out)<n:
        part=reader.read(n-len(out))
        if not part:raise ValueError('truncated research pipe frame')
        out.extend(part)
    return bytes(out)


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def write_message(writer,value):
    if type(value) is not dict:raise ValueError('object pipe message')
    raw=_canonical(value)
    if not 0<len(raw)<=CAP:raise ValueError('bounded research pipe message')
    writer.write(MAGIC+len(raw).to_bytes(4,'big')+raw);writer.flush()


def read_message(reader,cap=CAP):
    if type(cap) is not int or not 0<cap<=CAP:raise ValueError('qualified message cap')
    header=_exact(reader,len(MAGIC)+4)
    if header[:len(MAGIC)]!=MAGIC:raise ValueError('pipe version')
    length=int.from_bytes(header[-4:],'big')
    if not 0<length<=cap:raise ValueError('pipe length')
    raw=_exact(reader,length)
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise ValueError('duplicate pipe key')
            out[k]=v
        return out
    value=json.loads(raw,object_pairs_hook=unique)
    if type(value) is not dict or _canonical(value)!=raw:raise ValueError('noncanonical pipe encoding')
    return value
