"""Copy the pinned BearSSL control primitives, with upstream support headers."""
from pathlib import Path
import shutil
import subprocess
import sys
src = Path(sys.argv[1])
revision = '7bea48e5e850ab4cafbe68d3765cdaba13a86d6f'
if subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip() != revision:
    raise SystemExit('Wrong BearSSL revision')
dest = Path('Crypto/bearssl')
files = ['src/inner.h','src/config.h','src/hash/sha2small.c','src/mac/hmac.c',
         'src/kdf/hkdf.c','src/aead/gcm.c','src/symcipher/aes_ct_ctr.c',
         'src/hash/ghash_ctmul32.c','src/codec/dec32be.c','src/codec/enc32be.c',
         'src/codec/enc64be.c','LICENSE.txt']
files += [str(p.relative_to(src)) for p in (src/'inc').glob('*.h')]
for file in files:
    target = dest / file
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(src/file,target)

# Keep algorithms unchanged; erase explicit key/keystream scratch arrays.
# Compiler spills/register copies are still outside this best-effort guarantee.
patches = {
    'src/symcipher/aes_ct_ctr.c': [
        ('\t\t\tbreak;', '\t\t\tbp_wipe(q, sizeof(q));\n\t\t\tbp_wipe(tmp, sizeof(tmp));\n\t\t\tbreak;'),
        ('\t\tcc += 2;', '\t\tcc += 2;\n\t\tbp_wipe(q, sizeof(q));\n\t\tbp_wipe(tmp, sizeof(tmp));'),
        ('\treturn cc;', '\tbp_wipe(sk_exp, sizeof(sk_exp));\n\treturn cc;'),
    ],
    'src/mac/hmac.c': [
        ('\t(*hc)->state(hc, ks);', '\t(*hc)->state(hc, ks);\n\tbp_wipe(tmp, sizeof(tmp));'),
        ('\tprocess_key(&hc.vtable, kc->kso, key, key_len, 0x5C);',
         '\tprocess_key(&hc.vtable, kc->kso, key, key_len, 0x5C);\n\tbp_wipe(&hc, sizeof(hc));\n\tbp_wipe(kbuf, sizeof(kbuf));'),
        ('\treturn ctx->out_len;', '\tbp_wipe(&hc, sizeof(hc));\n\tbp_wipe(tmp, sizeof(tmp));\n\treturn ctx->out_len;'),
    ],
    'src/kdf/hkdf.c': [
        ('\thc->dig_len = br_hmac_size(&hc->u.hmac_ctx);',
         '\thc->dig_len = br_hmac_size(&hc->u.hmac_ctx);\n\tbp_wipe(&kc, sizeof(kc));\n\tbp_wipe(tmp, sizeof(tmp));'),
        ('\thc->chunk_num = 0;', '\thc->chunk_num = 0;\n\tbp_wipe(tmp, sizeof(tmp));'),
        ('\t\t\tbr_hmac_out(&hmac_ctx, hc->buf);',
         '\t\t\tbr_hmac_out(&hmac_ctx, hc->buf);\n\t\t\tbp_wipe(&hmac_ctx, sizeof(hmac_ctx));'),
    ],
}
for name, replacements in patches.items():
    target = dest/name
    text = target.read_text()
    text = text.replace('#include "inner.h"', '#include "inner.h"\n#include "crypto.h"')
    for old, new in replacements:
        if text.count(old) != 1:
            raise SystemExit(f'Adaptation no longer matches upstream: {name}')
        text = text.replace(old,new)
    target.write_text(text)
