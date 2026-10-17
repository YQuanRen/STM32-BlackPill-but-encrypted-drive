"""Exercise the actual C protocol/journal/MSC gate against Python cryptography.
No hardware access. Run without python -O.
"""
import ctypes as C
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'host'))
import bpctl as bp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

lib=C.CDLL(str(Path(sys.argv[1]).resolve()))
P,Z,I,U,Q=C.c_void_p,C.c_size_t,C.c_int,C.c_uint32,C.c_uint64
for name,args,ret in [
    ('sim_request',[P,Z,P],Z),('sim_fresh',[],None),('sim_boot',[],I),
    ('sim_cut',[I],None),('sim_erase_cut',[I],None),('sim_snapshot',[P],None),
    ('sim_restore',[P],None),('sim_corrupt',[U,C.c_uint8],None),('sim_allow',[I],None),
    ('sim_sd_fail',[I],None),('sim_time',[U],None),('sim_reset',[],None),
    ('sim_counter',[Q],None),('sim_counts',[Q,Q],None),('sim_clean',[],I),
    ('sim_state',[],I),('sim_epoch',[],Q),('sim_storage',[],I),('sim_raw_calls',[],I),
    ('sim_receive',[P,Z],I),('sim_get',[P],None),('sim_task',[],None),
    ('bp_sha',[P,Z,P],None),('bp_mac',[P,C.c_char_p,P,Z,P],None),
    ('bp_kdf',[P,Z,P,Z,P,Z,P,Z],None),('bp_gcm',[P,P,P,Z,P,Z,P,I],I),
    ('usb_config',[P],U),('usb_init',[],I),('usb_deinit',[],I),
    ('usb_setup',[U,U,U,U,U,P],I),('usb_receive',[P,U],I),('usb_msc_calls',[],U),
]:
    f=getattr(lib,name);f.argtypes=args;f.restype=ret
def buf(x):return C.create_string_buffer(x,max(1,len(x)))
def expect_error(fn):
    try:fn()
    except bp.ProtocolError:return
    raise AssertionError('Expected rejection')

# Published SHA-256, RFC4231 case 1 and RFC5869 case 1, NIST AES256-GCM zero case.
out=buf(bytes(32));lib.bp_sha(b'abc',3,out)
assert out.raw.hex()=='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
key=b'\x0b'*20+bytes(12);lib.bp_mac(key,b'',b'Hi There',8,out)
assert out.raw.hex()=='b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
out=buf(bytes(42));salt=bytes(range(13));info=bytes(range(240,250))
lib.bp_kdf(salt,len(salt),b'\x0b'*22,22,info,len(info),out,42)
assert out.raw.hex()=='3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
data=buf(bytes(16));tag=buf(bytes(16))
assert lib.bp_gcm(bytes(32),bytes(12),b'',0,data,16,tag,0)
assert data.raw.hex()=='cea7403d4d606b6e074ec5d3baf39d18'
assert tag.raw.hex()=='d0d1c8a799996bf0265b98b5d48ab919'
for n in [0,1,15,16,17,31,32,33,128,160]:
    for an in [0,1,15,16,17,48]:
        key=hashlib.sha256(bytes([n,an])).digest();iv=key[:12];aad=key[:1]*an
        plain=hashlib.shake_256(key).digest(n);data=buf(plain);tag=buf(bytes(16))
        assert lib.bp_gcm(key,iv,aad,an,data,n,tag,0)
        assert data.raw[:n]+tag.raw==AESGCM(key).encrypt(iv,plain,aad)
        assert lib.bp_gcm(key,iv,aad,an,data,n,tag,1) and data.raw[:n]==plain
        bad=buf(bytes([tag.raw[0]^1])+tag.raw[1:]);data=buf(plain)
        assert not lib.bp_gcm(key,iv,aad,an,data,n,bad,1)
        assert data.raw[:n]==bytes(n)
print('PASS: published SHA/HMAC/HKDF/AES256-GCM vectors and 60 independent AEAD cases',flush=True)

class Wire:
    def __init__(self):self.requests=[];self.responses=[]
    def exchange(self,request):
        self.requests.append(request);out=buf(b'\xa5'+bytes(256)+b'\x5a')
        n=lib.sim_request(request,len(request),C.byref(out,1))
        assert n<=256 and out.raw[0]==0xa5 and out.raw[-1]==0x5a
        response=out.raw[1:n+1];self.responses.append(response);return response

identity=bytes(range(1,13))+bytes(4)
auth,wrap=bp.file_keys(bytes(range(32)),identity)
assert auth!=wrap
def enrolled(mode=1):
    lib.sim_fresh();wire=Wire();client=bp.Client(wire)
    assert client.info()['state']==0
    assert lib.sim_storage()==0 and lib.sim_raw_calls()==0
    client.enroll(identity,mode,auth)
    assert lib.sim_state()==1 and lib.sim_epoch()==1
    return client,wire
def authenticated(mode=1):
    client,wire=enrolled(mode);client.authenticate(identity,mode,auth);client.ping();return client,wire

client,wire=enrolled()
expect_error(lambda:client.enroll(identity,1,auth))
expect_error(lambda:client.authenticate(identity,1,bytes(32)))
assert lib.sim_storage()==0 and lib.sim_raw_calls()==0
client.authenticate(identity,1,auth);client.ping()
expect_error(lambda:client.exchange(5,b'\x02',secure=True)) # production default gate
assert lib.sim_storage()==0
lib.sim_allow(1);client.exchange(5,b'\x02',secure=True)
assert lib.sim_storage()==31
# Invalid control traffic must not lock mounted media; reset must.
last=wire.requests[-1]
wire.exchange(last);assert lib.sim_storage()==31
lib.sim_reset();assert lib.sim_clean() and lib.sim_storage()==0
client.authenticate(identity,1,auth);client.exchange(5,b'\x02',secure=True)
lib.sim_sd_fail(1);assert lib.sim_storage()==0 and lib.sim_clean()
client,wire=authenticated(2);lib.sim_allow(1)
expect_error(lambda:client.exchange(5,b'\x02',secure=True))
expect_error(lambda:client.exchange(5,b'\x03'+bytes(32),secure=True))
assert lib.sim_storage()==0
client.exchange(5,b'\x03'+b'\x42'*32,secure=True);assert lib.sim_storage()==31
lib.sim_reset();assert lib.sim_clean() and lib.sim_storage()==0
print('PASS: both mode gates, wrong file/key, protected install, reset, fatal SD errors; actual MSC callbacks',flush=True)

# Host proof consumed on failure; expiry across uint32 tick wrap.
client,wire=enrolled();client.exchange(3,b'\x01'+bytes(32))
expect_error(lambda:client.exchange(4,bytes(32)))
expect_error(lambda:client.exchange(4,bytes(32)))
lib.sim_time(0xfffffff0);client.exchange(3,b'\x01'+bytes(32));lib.sim_time(0x2700)
assert client.wire.exchange(bp.header(4,11,32)+bytes(32))[8]==4
client,wire=authenticated();recorded=list(wire.requests);epoch=lib.sim_epoch()
lib.sim_reset();client.exchange(3,recorded[2][8:]) # a new challenge even with replayed host nonce
assert wire.exchange(recorded[3])[8]!=0
assert lib.sim_epoch()==epoch
assert lib.sim_boot() and lib.sim_epoch()>epoch
assert wire.exchange(recorded[3])[8]!=0
assert wire.exchange(recorded[4])[8]!=0
# Old valid challenge cannot get a host response for a fresh host nonce (future-session preplay).
class ReplayChallenge(Wire):
    def exchange(self,request):
        self.requests.append(request)
        response=bytearray(wire.responses[2]);response[2:6]=request[2:6]
        return bytes(response)
replay=ReplayChallenge();expect_error(lambda:bp.Client(replay).authenticate(identity,1,auth))
assert len(replay.requests)==1
client,wire=authenticated();lib.sim_time(60000)
expect_error(client.ping);assert lib.sim_storage()==0
client,wire=enrolled();lib.sim_counter(2**64-1)
expect_error(lambda:client.authenticate(identity,1,auth));assert lib.sim_storage()==0
for rx,tx in [(2**64-1,0),(0,2**64-1)]:
    client,wire=authenticated();lib.sim_counts(rx,tx);expect_error(client.ping)
print('PASS: single-use/expired challenges, USB/power-reset replay, preplay rejection and counter exhaustion',flush=True)

# Tamper every byte in an encrypted request: no altered request can authorize.
client,wire=authenticated()
plain=b'\x02';rid=900;aad=bp.header(5,rid,25)+struct.pack('<Q',client.tx)
packet=aad+AESGCM(client.send_key).encrypt(bytes(4)+aad[8:],plain,aad)
for i in range(len(packet)):
    client,wire=authenticated();lib.sim_allow(1)
    aad=bp.header(5,rid,25)+struct.pack('<Q',client.tx)
    packet=aad+AESGCM(client.send_key).encrypt(bytes(4)+aad[8:],plain,aad)
    bad=bytearray(packet);bad[i]^=1;wire.exchange(bytes(bad));assert lib.sim_storage()==0
    lib.sim_reset()
client,wire=authenticated();req=wire.requests[-1]
for n in range(len(req)):
    wire.exchange(req[:n]);assert lib.sim_storage()==0
for size in [257,512,4096]:assert wire.exchange(bytes(size))==b''
print('PASS: every-byte secure request tampering, truncation and oversize rejection',flush=True)

# Feature report framing and timeout, through actual C transport.
def report(payload,tid=7,total=None,off=0):
    total=len(payload) if total is None else total
    return (struct.pack('<BBHHH',1,1,tid,total,off)+payload).ljust(64,b'\0')
lib.sim_fresh();msg=bp.header(1,42,0)
for n in [0,1,63,65]:assert not lib.sim_receive(bytes(n),n)
assert not lib.sim_receive(report(msg,total=257),64)
assert not lib.sim_receive(report(msg,total=7),64)
assert not lib.sim_receive(report(msg,off=1),64)
assert not lib.sim_receive(report(msg)[:-1]+b'\x01',64)
enroll=bp.header(2,1,49)+identity+b'\x01'+auth
assert lib.sim_receive(report(enroll[:56],total=57),64)
assert not lib.sim_receive(report(enroll[56:],tid=8,total=57,off=56),64)
assert lib.sim_receive(report(enroll[:56],total=57),64)
lib.sim_time(1000);assert not lib.sim_receive(report(enroll[56:],total=57,off=56),64)
lib.sim_time(1001);assert lib.sim_receive(report(enroll[:56],total=57),64)
assert lib.sim_receive(report(enroll[56:],total=57,off=56),64)
assert not lib.sim_receive(report(msg),64);lib.sim_task()
assert not lib.sim_receive(report(msg),64)
r=buf(bytes(64));lib.sim_get(r);assert r.raw[8:]==(bp.header(130,1,33)+b'\0'+bp.mac(auth,b'BP1/enrolled',identity+b'\x01')).ljust(56,b'\0')
assert lib.sim_state()==1
lib.sim_get(r);assert r.raw[4:8]==bytes(4)
assert lib.sim_receive(report(msg),64);lib.sim_reset();lib.sim_task();lib.sim_get(r)
assert r.raw[4:8]==bytes(4)
print('PASS: HID fragment ordering, bounds, padding, timeout, queue backpressure and reset',flush=True)

# Run the actual hidapi framing client against the firmware transport with a fake
# HID device, including multi-report challenge replies and encrypted key requests.
class FakeHID:
    def send_feature_report(self,r):
        assert lib.sim_receive(r,len(r));return len(r)
    def get_feature_report(self,rid,n):
        assert (rid,n)==(1,64);lib.sim_task();r=buf(bytes(64));lib.sim_get(r);return r.raw
    def close(self):pass
lib.sim_fresh();hidwire=bp.HIDWire.__new__(bp.HIDWire);hidwire.dev=FakeHID();hidwire.transfer=0
client=bp.Client(hidwire);assert client.info()['device']==identity.hex()
client.enroll(identity,2,auth);client.authenticate(identity,2,auth);client.ping()
lib.sim_allow(1);client.exchange(5,b'\x03'+b'\x42'*32,secure=True)
assert lib.sim_storage()==31
lib.sim_reset();assert lib.sim_clean()
print('PASS: real Python HID framing client end-to-end with C firmware transport',flush=True)

lib.sim_fresh();assert lib.usb_init()==0
desc=buf(bytes(64));length=lib.usb_config(desc);assert length==57
cfg=desc.raw[:length];assert cfg[:9]==bytes([9,2,57,0,2,1,0,128,50])
off=9;interfaces=[];endpoints=[]
while off<len(cfg):
    n,kind=cfg[off:off+2];assert n>=2 and off+n<=len(cfg)
    if kind==4:interfaces.append((cfg[off+2],cfg[off+5]))
    if kind==5:endpoints.append(cfg[off+2])
    off+=n
assert interfaces==[(0,8),(1,3)] and endpoints==[0x81,1,0x82]
assert lib.usb_setup(0x81,6,0x2200,1,64,desc)==23
assert desc.raw[:3]==bytes([6,0,255]) and desc.raw[7:9]==bytes([0x85,1])
assert lib.usb_setup(0x81,6,0x2100,1,9,desc)==9 and desc.raw[:2]==bytes([9,0x21])
for bm,req,val,index,n in [(0x21,9,0x301,1,65),(0x21,9,0x302,1,64),
                         (0xa1,1,0x301,2,64),(0x21,9,0x301,257,64),
                         (0xa1,1,0x301,1,63),(0x81,6,0x2201,1,64)]:
    assert lib.usb_setup(bm,req,val,index,n,desc)==-1
before=lib.usb_msc_calls();assert lib.usb_setup(0xa1,254,0,0,1,desc)==0
assert lib.usb_msc_calls()==before+1
assert lib.usb_setup(0x21,9,0x301,1,64,desc)==0
assert lib.usb_receive(report(bp.header(1,42,0)),64)==0;lib.sim_task()
assert lib.usb_setup(0xa1,1,0x301,1,64,desc)==64 and desc.raw[8:16]==bp.header(129,42,27)
assert lib.usb_deinit()==0 and lib.sim_clean()
print('PASS: compiled USB composite descriptors, MSC routing, HID setup validation and EP0 exchange',flush=True)

# Fault injection at every byte of a record write, including commit word.
snap=buf(bytes(262144))
for cut in range(129):
    lib.sim_fresh();lib.sim_cut(cut);client=bp.Client(Wire())
    try:client.enroll(identity,1,auth)
    except bp.ProtocolError:pass
    issued=lib.sim_epoch() if lib.sim_state()==1 else 0
    lib.sim_cut(-1);lib.sim_boot()
    assert lib.sim_state() in ([0] if cut==0 else [1,2])
    if lib.sim_state()==1:assert lib.sim_epoch()>issued
    assert lib.sim_storage()==0
client,wire=enrolled();lib.sim_snapshot(snap)
for cut in range(129):
    lib.sim_restore(snap);lib.sim_cut(cut);lib.sim_boot()
    issued=lib.sim_epoch() if lib.sim_state()==1 else 1
    lib.sim_cut(-1);lib.sim_boot()
    assert lib.sim_state() in [1,2]
    if lib.sim_state()==1:assert lib.sim_epoch()>issued
    assert lib.sim_storage()==0
# Corrupt each byte of a committed record: never become virgin or issue old epochs.
for i in range(128):
    lib.sim_restore(snap);lib.sim_corrupt(i,1);lib.sim_boot();assert lib.sim_state()==2

def record(epoch):
    body=b'BPJ1'+struct.pack('<I',1)+identity+auth+struct.pack('<IQ',1,epoch)+bytes(24)
    assert len(body)==92
    return body+hashlib.sha256(body).digest()+bytes(4)
full=buf(b''.join(record(i) for i in range(1,1025))+b'\xff'*131072)
lib.sim_restore(full);assert lib.sim_boot() and lib.sim_epoch()==1025
assert lib.sim_boot() and lib.sim_epoch()==1026
for cut in range(129):
    lib.sim_restore(full);lib.sim_cut(cut);lib.sim_boot()
    issued=lib.sim_epoch() if lib.sim_state()==1 else 1024
    lib.sim_cut(-1);lib.sim_boot()
    assert lib.sim_state() in [1,2]
    if lib.sim_state()==1:assert lib.sim_epoch()>issued
# Active bank 1 full, bank 0 stale: exercise interrupted erase of nonblank old bank.
both=buf(b''.join(record(i) for i in range(1,2049)))
for cut in [0,1,4,60,124,125,127,128,129,65536,131071,131072]:
    lib.sim_restore(both);lib.sim_erase_cut(cut);lib.sim_boot()
    lib.sim_erase_cut(-1);lib.sim_boot()
    assert lib.sim_state() in [1,2]
    if lib.sim_state()==1:assert lib.sim_epoch()>2048
overflow=buf(record(2**64-1)+b'\xff'*(262144-128))
lib.sim_restore(overflow);assert not lib.sim_boot() and lib.sim_state()==2
print('PASS: 387 append/enrollment/rollover power cuts, 128 corruptions, 12 torn erases and epoch exhaustion',flush=True)

with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]/'build') as temp:
    path=Path(temp)/'credential.json';bp.save_file(path,identity,bytes(range(32)),1)
    assert bp.load_file(path)==(identity,bytes(range(32)),1)
    try:bp.save_file(path,identity,bytes(32),2)
    except FileExistsError:pass
    else:raise AssertionError('Overwrote credential')
    path.write_text('x'*4097);expect_error(lambda:bp.load_file(path))
print('PASS: credential persistence, strict file bounds and no overwrite',flush=True)
