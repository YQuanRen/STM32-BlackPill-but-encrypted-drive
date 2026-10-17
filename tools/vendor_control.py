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
