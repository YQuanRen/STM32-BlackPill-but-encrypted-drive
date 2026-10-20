"""Version-1 authenticated volume metadata and password/file key wrapping."""
import hashlib
import hmac
import secrets
import struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from bpctl import file_keys, kdf, mac, ProtocolError

def aad(h): return bytes(h[:12]+h[16:128])

def kek(password, root, h):
    encoded=password.encode('utf-8')
    if not 1<=len(encoded)<=1024: raise ProtocolError('Password must be 1..1024 UTF-8 bytes')
    # Bounds checked before this function by validate(), or fixed by build().
    pw=hash_secret_raw(encoded,bytes(h[100:116]),3,65536,1,32,Type.ID,version=19)
    _,wrap=file_keys(root,bytes(h[16:32]))
    salt=hashlib.sha256(b'BP1/wrap-salt'+bytes(h[16:48])).digest()
    return kdf(pw+wrap,salt,b'BP1/data-wrap')

def validate(h, identity, auth, ready=True):
    if len(h)!=256 or not hmac.compare_digest(h[224:],mac(auth,b'BP1/header',h[:224])):
        raise ProtocolError('Header authentication failed')
    version,state=struct.unpack_from('<II',h,8)
    physical,logical,mode,sector=struct.unpack_from('<QQII',h,64)
    if (h[:8]!=b'BPVOL001' or version!=1 or state!=(2 if ready else 1) or
        h[16:32]!=identity or h[32:48]==bytes(16) or mode not in (1,2) or sector!=512 or
        not 16<physical<=2**32-1 or logical!=physical-16 or any(h[208:224])):
        raise ProtocolError('Invalid volume metadata')
    if mode==1 and any(h[88:208]):raise ProtocolError('Invalid plaintext-mode metadata')
    if mode==2 and struct.unpack_from('<III',h,88)!=(65536,3,1):
        raise ProtocolError('Unsupported password KDF parameters')
    return mode

def build(identity, root, mode, cid, physical, password=None):
    if len(identity)!=16 or len(cid)!=16 or mode not in (1,2) or not 16<physical<=2**32-1:
        raise ProtocolError('Invalid setup target')
    auth,_=file_keys(root,identity)
    h=bytearray(256);h[:8]=b'BPVOL001';struct.pack_into('<II',h,8,1,1)
    h[16:32]=identity;h[32:48]=secrets.token_bytes(16);h[48:64]=cid
    struct.pack_into('<QQII',h,64,physical,physical-16,mode,512)
    key=bytes(32)
    if mode==2:
        struct.pack_into('<III',h,88,65536,3,1);h[100:116]=secrets.token_bytes(16)
        h[116:128]=secrets.token_bytes(12);key=secrets.token_bytes(32)
        h[128:176]=AESGCM(kek(password,root,h)).encrypt(bytes(h[116:128]),key,aad(h))
        h[176:208]=mac(key,b'BP1/data-check',aad(h))
    h[224:]=mac(auth,b'BP1/header',h[:224]);validate(bytes(h),identity,auth,False)
    return bytes(h),key

def unwrap(h,identity,root,password):
    auth,_=file_keys(root,identity);mode=validate(h,identity,auth)
    if mode!=2:raise ProtocolError('This volume is not encrypted')
    try:key=AESGCM(kek(password,root,h)).decrypt(h[116:128],h[128:176],aad(h))
    except Exception as exc:raise ProtocolError('Wrong password/file or damaged wrapped key') from exc
    if not hmac.compare_digest(mac(key,b'BP1/data-check',aad(h)),h[176:208]):
        raise ProtocolError('Data key verification failed')
    return key

def status(client):
    r=client.exchange(5,b'\x06',secure=True)
    if len(r)!=30:raise ProtocolError('Invalid initialization status')
    state,mode,done,total=struct.unpack_from('<BBII',r)
    return dict(state=state,mode=mode,done=done,total=total,cid=r[10:26],physical=struct.unpack_from('<I',r,26)[0])

def read_header(client,identity,auth):
    h=b''.join(client.exchange(5,b'\x07'+struct.pack('<HB',off,128),secure=True) for off in [0,128])
    validate(h,identity,auth);return h

def start_setup(client,h,key):
    payload=h+key
    if len(payload)!=288:raise ProtocolError('Invalid setup payload')
    for off in range(0,288,128):
        client.exchange(5,b'\x04'+struct.pack('<H',off)+payload[off:off+128],secure=True)
    client.exchange(5,b'\x05',secure=True)
