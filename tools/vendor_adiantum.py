"""Reproduce the trimmed MIT primitive sources from pinned local checkouts.

Usage: python tools/vendor_adiantum.py GOOGLE_CHECKOUT BEARSSL_CHECKOUT
See Crypto/README.md for revisions and adaptation details.
"""
from pathlib import Path
import shutil
import sys
import subprocess

google, bear = map(Path, sys.argv[1:])
for checkout, revision in [(google, '4feeb5aada81dc2f319996acd4ac95a2a07c99a4'),
                           (bear, '7bea48e5e850ab4cafbe68d3765cdaba13a86d6f')]:
    actual = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != revision:
        raise SystemExit(f'Unexpected source revision: {checkout}: {actual}')
dest = Path('Crypto/vendor')
dest.mkdir(parents=True, exist_ok=True)
g = google / 'benchmark/src'
for name in ['aes_ct.c', 'aes_ct_enc.c', 'aes_ct_dec.c']:
    text = (bear / 'src/symcipher' / name).read_text()
    text = text.replace('"inner.h"', '"primitives.h"')
    if name == 'aes_ct.c':
        text = text.replace('return q[0];', 'uint32_t result = q[0];\n\tcrypto_wipe(q, sizeof(q));\n\treturn result;')
        text = text.replace('\treturn num_rounds;', '\tcrypto_wipe(skey, sizeof(skey));\n\treturn num_rounds;')
    (dest / name).write_text(text)
shutil.copyfile(bear / 'LICENSE.txt', dest / 'LICENSE.BearSSL')
shutil.copyfile(google / 'LICENSE', dest / 'LICENSE.Google')
text = (g / 'poly1305.c').read_text().split('/* Poly1305 benchmarking */')[0]
start = text.index('static void poly1305_key_powers')
end = text.index('void poly1305_setkey')
text = text[:start] + text[end:]
text = text.replace('\tpoly1305_key_powers(key);', '')
text = text.replace('"poly1305.h"', '"primitives.h"')
import re
text = re.sub(r'out->w32\[(\d)\] = cpu_to_le32\((.*)\);',
              r'put_unaligned_le32(\2, out->bytes + 4 * \1);', text)
(dest / 'poly1305.c').write_text(text)
text = (g / 'nh.c').read_text()
text = text[:text.index('#if 0')] + text[text.index('#else /* optimized generic version */') + len('#else /* optimized generic version */'):text.index('#endif /* optimized generic version */')]
text = text.replace('#include "nh.h"', '#include "primitives.h"').replace('#include "testvec.h"', '')
(dest / 'nh.c').write_text(text)
text = (g / 'chacha.c').read_text()
text = text[:text.index('#include')] + '#include "primitives.h"\n\n' + text[text.index('void chacha_setkey'):text.index('static inline void __maybe_unused')]
tail = (g / 'chacha.c').read_text()
tail = tail[tail.index('/* ChaCha stream cipher */'):tail.index('static void fuzz_chacha')]
tail = re.sub(r'#ifdef HAVE_.*?\n.*?#endif\n', '', tail, flags=re.S)
text += tail
text = text.replace('\n\tchacha_generic(ctx,', '\n    (void)simd;\n\tchacha_generic(ctx,')
text = text.replace('\n\tu32 x[16];\n\n\tmemcpy(x, state', '\n\tu32 x[16];\n    (void)simd;\n\n\tmemcpy(x, state')
text = text.replace('({', 'do {').replace('; })', '; } while (0)')
# Serialize bytewise, independent of host endianness.
text = text.replace('stream[i] = cpu_to_le32(x[i] + state[i]);', 'put_unaligned_le32(x[i] + state[i], (u8 *)stream + 4 * i);')
# Wipe transient key material, including the last keystream block.
text = text.replace('\n}\n\n/* XChaCha', '\n    crypto_wipe(x, sizeof(x));\n}\n\n/* XChaCha')
text = text.replace('\tchacha(&subctx, dst, src, nbytes, real_iv, simd);', '\tchacha(&subctx, dst, src, nbytes, real_iv, simd);\n    crypto_wipe(&subctx, sizeof(subctx));\n    crypto_wipe(state, sizeof(state));')
text = text.replace('\tstate[12]++;', '\tstate[12]++;\n    crypto_wipe(x, sizeof(x));')
text = text.replace('\n}\n\n/* ChaCha stream cipher */', '\n    crypto_wipe(state, sizeof(state));\n    crypto_wipe(stream, sizeof(stream));\n}\n\n/* ChaCha stream cipher */')
(dest / 'chacha.c').write_text(text)
ref = Path('tests/crypto/reference')
ref.mkdir(parents=True, exist_ok=True)
for name in ['adiantum', 'hbsh', 'nh', 'poly1305', 'cipher', 'latindance', 'xconstruct', 'aes']:
    shutil.copyfile(google / 'python' / (name + '.py'), ref / (name + '.py'))
shutil.copyfile(google / 'LICENSE', ref / 'LICENSE')
vectors = list((google / 'test_vectors/ours/Adiantum').glob('*XChaCha12*'))
for p in vectors:
    shutil.copyfile(p, ref / p.name)
