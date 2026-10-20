"""Actual protocol, journal, volume and MSC callbacks; memory-backed SD only."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'host'),str(ROOT/'tests/crypto/reference')]
import bpctl as bp
import volume
import adiantum
lib=C.CDLL(str(Path(sys.argv[1]).resolve()))
P,U,I,Z=C.c_void_p,C.c_uint32,C.c_int,C.c_size_t
for name,args,ret in [
    ('sim_fresh',[],None),('sim_boot',[],I),('sim_request',[P,Z,P],Z),
    ('sim_reset',[],None),('sim_step',[],None),('sim_time',[U],None),
    ('sim_fault',[I,I,I],None),('sim_card',[I,I],None),('sim_raw',[P],None),
    ('sim_raw_restore',[P],None),('sim_flash',[P],None),('sim_writes',[],I),
    ('sim_reads',[],I),('sim_state',[],I),('sim_clean',[],I),
    ('sim_geometry',[U],None),('sim_flash_cut',[I],None),
    ('sim_read',[U,P,C.c_uint16],I),('sim_write',[U,P,C.c_uint16],I),('sim_capacity',[],U)]:
    f=getattr(lib,name);f.argtypes=args;f.restype=ret
def buf(x):return C.create_string_buffer(x,len(x))
def reject(fn):
    try:fn()
    except bp.ProtocolError:return
    raise AssertionError('Expected rejection')
class Wire:
    def exchange(self,p):
        out=C.create_string_buffer(256);n=lib.sim_request(p,len(p),out);return out.raw[:n]
identity=bytes(range(1,13))+bytes(4)
root=hashlib.sha256(b'storage test fixture only').digest()
auth,_=bp.file_keys(root,identity)
password='Test password \u2603'
def session(op=1):
    c=bp.Client(Wire());c.authenticate(identity,c.info()['mode'],auth,op);return c
def fresh(mode=2):
    lib.sim_fresh();c=bp.Client(Wire());c.enroll(identity,mode,auth);return session(2)
def proposal(mode=2):return volume.build(identity,root,mode,b'1'*16,64,password)
def finish():
    for _ in range(49):lib.sim_step()
    assert lib.sim_state()==2 and lib.sim_clean() and not lib.sim_capacity()
def raw():
    p=C.create_string_buffer(64*512);lib.sim_raw(p);return p.raw
def unlock(key,mode=2):
    c=session();h=volume.read_header(c,identity,auth)
    c.exchange(5,b'\x03'+key if mode==2 else b'\x02',secure=True)
    assert lib.sim_capacity()==48;return c,h
ref=adiantum.Adiantum();ref.variant=json.loads((ROOT/'tests/crypto/reference/Adiantum_XChaCha12_32_AES256.json').read_text())[0]['cipher']
for mode in (1,2):
    c=fresh(mode);h,key=proposal(mode)
    p=buf(bytes(512));before=lib.sim_reads()
    assert lib.sim_read(0,p,1)!=0 and lib.sim_write(0,p,1)!=0 and lib.sim_reads()==before
    volume.start_setup(c,h,key);assert not lib.sim_capacity();finish()
    disk=raw();assert disk[:4096]==disk[4096:8192]
    for lba in range(48):
        expected=bytes(512) if mode==1 else ref.encrypt(bytes(512),key=key,tweak=struct.pack('<Q',lba)+bytes(24))
        assert disk[(lba+16)*512:(lba+17)*512]==expected
    c,ready=unlock(key,mode)
    if mode==2:
        assert volume.unwrap(ready,identity,root,password)==key
        reject(lambda:volume.unwrap(ready,identity,root,'wrong'))
        reject(lambda:volume.unwrap(ready,identity,bytes(32),password))
    payload=hashlib.shake_256(b'file contents').digest(48*512);source=buf(payload)
    assert lib.sim_write(0,source,48)==0 and source.raw==payload
    disk=raw();assert disk[:8192]==ready+bytes(4096-256)+ready+bytes(4096-256)
    for lba in (0,1,47):
        expected=payload[lba*512:(lba+1)*512]
        if mode==2:expected=ref.encrypt(expected,key=key,tweak=struct.pack('<Q',lba)+bytes(24))
        assert disk[(lba+16)*512:(lba+17)*512]==expected
    reject(lambda:volume.start_setup(c,*proposal(mode))) # No mounted setup.
    lib.sim_reset();assert lib.sim_clean() and not lib.sim_capacity()
    unlock(key,mode);out=buf(bytes(len(payload)));assert lib.sim_read(0,out,48)==0
    assert hashlib.sha256(out.raw).digest()==hashlib.sha256(payload).digest()
    for lba,n in [(48,1),(47,2),(2**32-1,2),(0,0),(0,65535)]:
        assert lib.sim_write(lba,source,n)!=0
        if not lib.sim_capacity():unlock(key,mode)
    lib.sim_card(1,1);assert lib.sim_read(0,out,1)!=0 and lib.sim_clean()
    lib.sim_card(1,0);unlock(key,mode);lib.sim_fault(-1,1,0)
    assert lib.sim_read(0,out,1)!=0 and lib.sim_clean()
    lib.sim_fault(-1,0,0);unlock(key,mode);lib.sim_fault(1,0,0)
    assert lib.sim_write(0,source,2)!=0 and source.raw==payload and lib.sim_clean()
    print(f'PASS mode {mode}: zero initialization, reference ciphertext, mapping, reconnect hash, bounds, card swap, SD failures',flush=True)

# Reuse a single encrypted proposal to keep the fault matrix independent of Argon2 speed.
h,key=proposal();c=fresh();volume.start_setup(c,h,key);finish();good=raw()
flash=C.create_string_buffer(2*128*1024);lib.sim_flash(flash)
assert key not in flash.raw and key not in good[:8192] and root not in flash.raw
for off in list(range(256))+[256,511,512,4095,4096,4352,8191]:
    lib.sim_reset();damaged=bytearray(good);damaged[off]^=1;lib.sim_raw_restore(bytes(damaged))
    c=session();reject(lambda:volume.read_header(c,identity,auth));assert not lib.sim_capacity()
lib.sim_raw_restore(good);lib.sim_reset();c=session()
reject(lambda:c.exchange(5,b'\x03'+bytes(32),secure=True));assert not lib.sim_capacity() and lib.sim_clean()
lib.sim_card(0,0);reject(lambda:volume.status(c));lib.sim_card(1,0)
lib.sim_reset();lib.sim_card(1,1);c=session();reject(lambda:volume.read_header(c,identity,auth));lib.sim_card(1,0)
# Authentic but invalid KDF parameters must be rejected before password allocation.
bad=bytearray(good[:256]);struct.pack_into('<I',bad,88,2**32-1);bad[224:]=bp.mac(auth,b'BP1/header',bad[:224])
reject(lambda:volume.unwrap(bytes(bad),identity,root,password))
print('PASS: 263 header/padding corruptions, wrong key/password/file, absent/swapped card, bounded KDF, no persistent plaintext keys',flush=True)

# Interrupt every SD write boundary, including both initializing and both ready copies.
for cut in range(80):
    c=fresh();lib.sim_fault(cut,0,0)
    try:volume.start_setup(c,h,key)
    except bp.ProtocolError:pass
    for _ in range(49):lib.sim_step()
    assert not lib.sim_capacity()
    lib.sim_fault(-1,0,0);lib.sim_boot();c=session()
    reject(lambda:volume.read_header(c,identity,auth));assert lib.sim_clean()
# Explicit restart changes volume binding and works after a failed initialization.
c=session(2);replacement,newkey=proposal();volume.start_setup(c,replacement,newkey);finish();unlock(newkey)
lib.sim_reset();lib.sim_raw_restore(good);c=session();reject(lambda:volume.read_header(c,identity,auth))
print('PASS: all 80 initialization write interruption points, explicit restart and old-volume rollback rejection',flush=True)

# A failed mode-change commit must not expose the old ready volume in the old mode.
c=fresh();volume.start_setup(c,h,key);finish();old=raw();plain,zero=proposal(1)
c=session(2);lib.sim_fault(0,0,0);reject(lambda:volume.start_setup(c,plain,zero))
lib.sim_fault(-1,0,0);lib.sim_boot();c=session();assert c.info()['mode']==1
reject(lambda:c.exchange(5,b'\x02',secure=True));assert raw()==old
c=session(2);plain,zero=proposal(1);volume.start_setup(c,plain,zero);finish();unlock(zero,1)
c=fresh();lib.sim_fault(-1,0,1);reject(lambda:volume.start_setup(c,h,key));assert lib.sim_clean()
c=fresh();c.exchange(5,b'\x04\x00\x00'+h[:128],secure=True);lib.sim_time(60000);lib.sim_step();assert lib.sim_clean()
c=fresh()
reject(lambda:c.exchange(5,b'\x04\x01\x00x',secure=True));assert lib.sim_clean()
c=session();reject(lambda:volume.start_setup(c,h,key));assert lib.sim_writes()==0
print('PASS: durable mode switch, readback verification, staging expiry/order and setup authorization',flush=True)

for count in (0,16,63,65,2**32-1):
    c=fresh();lib.sim_geometry(count);reject(lambda:volume.start_setup(c,h,key))
    assert lib.sim_writes()==0 and lib.sim_clean()
for off in (0,8,12,16,32,48,64,72,80,84,88,92,96,176,208):
    c=fresh();bad=bytearray(h);bad[off]^=1;bad[224:]=bp.mac(auth,b'BP1/header',bad[:224])
    reject(lambda:volume.start_setup(c,bytes(bad),key));assert lib.sim_writes()==0
# A journal binding failure must precede all SD mutation, including torn commit.
for cut in range(128):
    c=fresh();before=raw();lib.sim_flash_cut(cut)
    reject(lambda:volume.start_setup(c,h,key));assert raw()==before and lib.sim_writes()==0 and lib.sim_clean()
print('PASS: geometry bounds, authenticated malformed fields, all 128 binding journal write interruptions precede SD writes',flush=True)

# Exercise the CLI's actual setup/unlock orchestration with no physical HID access.
import contextlib
import io
import tempfile
from unittest.mock import patch
class CLIWire(Wire):
    def __init__(self,path):pass
    def close(self):pass
def advance(_):
    for _ in range(49):lib.sim_step()
with tempfile.TemporaryDirectory() as directory:
    path=str(Path(directory)/'auth.json')
    args=['bpctl','setup','--device',identity.hex(),'--file',path,'--mode','encrypted']
    lib.sim_fresh()
    with patch.object(bp,'devices',return_value=[{'path':b'sim'}]),patch.object(bp,'HIDWire',CLIWire),patch.object(bp.time,'sleep',advance),contextlib.redirect_stdout(io.StringIO()):
        with patch.object(sys,'argv',args),patch('builtins.input',return_value=f'ERASE {identity.hex()} '+('31'*16)),patch.object(bp.getpass,'getpass',return_value=password):bp.main()
        assert lib.sim_capacity()==48 and Path(path).exists()
        lib.sim_reset()
        with patch.object(sys,'argv',args[:1]+['unlock']+args[2:-2]),patch.object(bp.getpass,'getpass',return_value='wrong'):reject(bp.main)
        assert not lib.sim_capacity()
        with patch.object(sys,'argv',args[:1]+['unlock']+args[2:-2]),patch.object(bp.getpass,'getpass',return_value=password):bp.main()
        assert lib.sim_capacity()==48
        lib.sim_reset();before=lib.sim_writes()
        with patch.object(sys,'argv',args),patch('builtins.input',return_value='cancel'):reject(bp.main)
        assert lib.sim_writes()==before
print('PASS: actual CLI enrollment/setup/progress/unlock, wrong password and destructive-confirmation cancellation',flush=True)
