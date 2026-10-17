"""Host KAT, independent-reference and API/buffer tests. No hardware access."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'reference'))
import adiantum

lib = C.CDLL(str(Path(sys.argv[1]).resolve()))
P, Z, I = C.c_void_p, C.c_size_t, C.c_int
for name, args in {
    'test_init': [P, P, Z], 'test_clear': [P],
    'test_crypt': [P, P, Z, P, Z, P, Z, I],
    'test_sector': [P, P, Z, P, C.c_uint64, I],
    'test_context_size': [],
}.items():
    getattr(lib, name).argtypes = args
    getattr(lib, name).restype = None if name == 'test_clear' else Z if name == 'test_context_size' else I
ctx_size = lib.test_context_size()
ctx = (C.c_uint64 * ((ctx_size + 7) // 8))()
def buf(b): return C.create_string_buffer(b, max(1, len(b)))
def run(key, tweak, plain, expected, lba=None):
    k, t = buf(key), buf(tweak)
    assert lib.test_init(ctx, k, len(key)) == 0
    # Unaligned, guarded data; test both directions independently and in-place.
    for dec, source, wanted in [(0, plain, expected), (1, expected, plain)]:
        n = len(source)
        s = buf(b'\xa5' + source + b'\x5a')
        d = buf(b'\xa5' + b'\xcc' * n + b'\x5a')
        sp, dp = C.byref(s, 1), C.byref(d, 1)
        assert lib.test_crypt(ctx, dp, n, sp, n, t, len(tweak), dec) == 0
        assert d.raw == b'\xa5' + wanted + b'\x5a'
        assert s.raw == b'\xa5' + source + b'\x5a'
        assert lib.test_crypt(ctx, sp, n, sp, n, t, len(tweak), dec) == 0
        assert s.raw == b'\xa5' + wanted + b'\x5a'
        if lba is not None:
            s = buf(source)
            assert lib.test_sector(ctx, dp, n, s, lba, dec) == 0
            assert d.raw == b'\xa5' + wanted + b'\x5a'

vectors = json.loads((ROOT / 'reference/Adiantum_XChaCha12_32_AES256.json').read_text())
ref = adiantum.Adiantum()
ref.variant = vectors[0]['cipher']
for v in vectors:
    key = bytes.fromhex(v['input']['key_hex'])
    tweak = bytes.fromhex(v['input']['tweak_hex'])
    plain, encrypted = (bytes.fromhex(v[x + '_hex']) for x in ['plaintext', 'ciphertext'])
    run(key, tweak, plain, encrypted)
print(f'PASS: {len(vectors)} official vectors, encrypt/decrypt, in-place, unaligned, guards')

count = 0
for ki in range(4):
    key = hashlib.sha256(f'adiantum-test-key-{ki}'.encode()).digest()
    for lba in [0, 1, 255, 256, 2**32-1, 2**32, 2**63, 2**64-1]:
        tweak = lba.to_bytes(8, 'little') + bytes(24)
        for pattern in [bytes(512), bytes([255])*512, bytes(range(256))*2,
                        hashlib.shake_256(key+tweak).digest(512)]:
            expected = ref.encrypt(pattern, key=key, tweak=tweak)
            assert ref.decrypt(expected, key=key, tweak=tweak) == pattern
            run(key, tweak, pattern, expected, lba)
            count += 1
print(f'PASS: {count} independent Python sector comparisons across keys/LBAs/patterns')

# Extra NH and stream boundaries, including non-block-aligned tweaks.
for n in [16,17,31,32,63,64,65,511,512,513,1023,1024,1025,1039,1040,1041,2049,4095,4096]:
    for tn in [0,1,15,16,17,31,32]:
        key = hashlib.sha256(bytes([tn])).digest()
        tweak = bytes(range(tn))
        plain = hashlib.shake_256(key + n.to_bytes(2,'little')).digest(n)
        run(key, tweak, plain, ref.encrypt(plain,key=key,tweak=tweak))
print('PASS: 133 independent length/tweak boundary comparisons')

k,t,s,d = buf(bytes(32)),buf(bytes(33)),buf(bytes(8192)),buf(b'\xcc'*8192)
assert lib.test_init(ctx,k,32) == 0
base = [ctx,d,512,s,512,t,32,0]
cases = [(0,None),(1,None),(2,511),(3,None),(4,0),(4,15),(4,4097),
         (4,Z(-1).value),(5,None),(6,33),(6,Z(-1).value),(7,-1),(7,2)]
for index,value in cases:
    args = base.copy(); args[index] = value
    assert lib.test_crypt(*args) == -1
    assert d.raw == b'\xcc'*8192
for delta in [-1,1,16,511]:
    original = s.raw
    assert lib.test_crypt(ctx,C.byref(s,512+delta),512,C.byref(s,512),512,t,32,0) == -1
    assert s.raw == original
for args in [[ctx,d,512,s,512,d,32,0], [ctx,ctx,512,s,512,t,32,0],
             [ctx,d,512,ctx,512,t,32,0], [ctx,d,512,s,512,ctx,32,0]]:
    before = bytes(ctx)
    assert lib.test_crypt(*args) == -1
    assert bytes(ctx) == before
    assert d.raw == b'\xcc'*8192
assert lib.test_crypt(ctx,d,512,s,512,None,0,0) == 0
for key,kn in [(None,32),(k,0),(k,31),(k,33),(ctx,32)]:
    assert lib.test_init(ctx,key,kn) == -1
    assert bytes(ctx) == bytes(len(bytes(ctx)))
    assert lib.test_crypt(*base) == -1
    assert lib.test_init(ctx,k,32) == 0
assert lib.test_init(None,k,32) == -1
lib.test_clear(ctx)
lib.test_clear(None)
assert bytes(ctx) == bytes(len(bytes(ctx)))
assert lib.test_crypt(*base) == -1
print(f'PASS: invalid input/state, overlap, output preservation and clear; context={ctx_size} bytes')
