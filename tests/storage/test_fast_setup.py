"""Fast-setup bounds, compatibility and interrupted commits on sparse large SDs."""
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
    ('sim_reset',[],None),('sim_step',[],None),('sim_geometry',[U],None),
    ('sim_fault',[I,I,I],None),('sim_torn',[I],None),('sim_card',[I,I],None),
    ('sim_writes',[],I),('sim_state',[],I),('sim_clean',[],I),
    ('sim_raw_sector',[U,P],None),('sim_read',[U,P,C.c_uint16],I),
    ('sim_write',[U,P,C.c_uint16],I),('sim_capacity',[],U),
]:
    f=getattr(lib,name);f.argtypes=args;f.restype=ret
identity=bytes(range(1,13))+bytes(4)
root=hashlib.sha256(b'fast setup fixture').digest()
auth,_=bp.file_keys(root,identity)
ref=adiantum.Adiantum()
ref.variant=json.loads((ROOT/'tests/crypto/reference/Adiantum_XChaCha12_32_AES256.json').read_text())[0]['cipher']
class Wire:
    def exchange(self,p):
        out=C.create_string_buffer(256);n=lib.sim_request(p,len(p),out);return out.raw[:n]
def reject(fn):
    try:fn()
    except bp.ProtocolError:return
    raise AssertionError('Expected rejection')
def session(op=1):
    c=bp.Client(Wire());c.authenticate(identity,c.info()['mode'],auth,op);return c
def fresh(physical,mode):
    lib.sim_fresh();lib.sim_geometry(physical)
    c=bp.Client(Wire());c.enroll(identity,mode,auth);return session(2)
def raw(lba):
    out=C.create_string_buffer(512);lib.sim_raw_sector(lba,out);return out.raw
def finish(c,total):
    for n in range(total):
        s=volume.status(c);assert s['done']==n and s['total']==total and s['state']==1
        lib.sim_step()
    assert not lib.sim_capacity()
    lib.sim_step()
    s=volume.status(c);assert s['state']==2 and s['done']==s['total']==total
    assert lib.sim_clean()
def unlock(key,mode):
    c=session();h=volume.read_header(c,identity,auth)
    if mode==2:assert volume.unwrap(h,identity,root,'test password')==key
    c.exchange(5,b'\x02' if mode==1 else b'\x03'+key,secure=True)
    return h

for mode in (1,2):
    for physical in (17,49,50,51,82,83,84,256,15625000,122167296,2**32-1):
        c=fresh(physical,mode)
        h,key=volume.build(identity,root,mode,b'1'*16,physical,'test password')
        volume.start_setup(c,h,key)
        total=volume.setup_total(physical);finish(c,total)
        assert lib.sim_writes()==32+total
        logical=physical-16
        targets=set(range(min(34,logical)))|set(range(max(0,logical-33),logical))
        assert len(targets)==total
        for lba in targets:
            expected=bytes(512) if mode==1 else ref.encrypt(bytes(512),key=key,tweak=struct.pack('<Q',lba)+bytes(24))
            assert raw(lba+16)==expected
        for lba in {34,logical//2,logical-34}:
            if 0<=lba<logical and lba not in targets:
                assert raw(lba+16)==b'\xa5'*512  # Old data is deliberately not erased.
        lib.sim_boot();ready=unlock(key,mode);assert struct.unpack_from('<I',ready,8)[0]==2
        assert lib.sim_capacity()==logical
        # Partition boundary reads are zeros through the unlocked view.
        out=C.create_string_buffer(512)
        for lba in (0,logical-1):
            assert lib.sim_read(lba,out,1)==0 and out.raw==bytes(512)
        if logical>67:
            assert lib.sim_read(34,out,1)==0
            expected=b'\xa5'*512 if mode==1 else ref.decrypt(b'\xa5'*512,key=key,tweak=struct.pack('<Q',34)+bytes(24))
            assert out.raw==expected
        data=hashlib.shake_256(b'new file').digest(512)
        source=C.create_string_buffer(data,512)
        lba=logical//2
        assert lib.sim_write(lba,source,1)==0 and source.raw==data
        lib.sim_reset();unlock(key,mode)
        assert lib.sim_read(lba,out,1)==0 and out.raw==data
    print(f'PASS mode {mode}: tiny/overlap/large/UINT32 geometries; <=99 writes, reference metadata crypto, untouched old data, reconnect file integrity',flush=True)

physical=122167296
for mode in (1,2):
    h,key=volume.build(identity,root,mode,b'1'*16,physical,'test password')
    for cut in range(99):
        c=fresh(physical,mode);lib.sim_fault(cut,0,0)
        try:volume.start_setup(c,h,key)
        except bp.ProtocolError:pass
        for _ in range(68):lib.sim_step()
        assert not lib.sim_capacity()
        lib.sim_fault(-1,0,0);lib.sim_boot();c=session()
        reject(lambda:volume.read_header(c,identity,auth))
        assert lib.sim_clean()
    # Tears in initial headers, first/last metadata sectors, and final ready markers.
    for cut in (14,15,16,49,82,97,98):
        for prefix in (1,64,128,224,255):
            c=fresh(physical,mode);lib.sim_fault(cut,0,0);lib.sim_torn(prefix)
            try:volume.start_setup(c,h,key)
            except bp.ProtocolError:pass
            for _ in range(68):lib.sim_step()
            lib.sim_fault(-1,0,0);lib.sim_torn(-1);lib.sim_boot();c=session()
            reject(lambda:volume.read_header(c,identity,auth))
    print(f'PASS mode {mode}: all 99 interrupted writes and 35 torn-sector cases remain locked after reboot',flush=True)

# Legacy v1 full-initialization volumes remain readable; no silent format migration.
for mode in (1,2):
    c=fresh(128,mode)
    h,key=volume.build(identity,root,mode,b'1'*16,128,'test password',version=1)
    volume.start_setup(c,h,key);finish(c,112);assert lib.sim_writes()==144
    lib.sim_boot();ready=unlock(key,mode);assert struct.unpack_from('<I',ready,8)[0]==1
print('PASS: v1 full-initialization/progress/unlock compatibility in both modes',flush=True)
