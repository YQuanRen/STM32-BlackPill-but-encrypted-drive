# Standalone Adiantum (milestone 2)

`adiantum.h` is the public interface. The module implements standard
Adiantum-XChaCha12-AES256 with 16..4096-byte messages and 0..32-byte tweaks.
The sector helper uses exactly 512 bytes and `LE64(logical LBA) || zero[24]`.
No heap, variable-length arrays, SD operations, USB calls or persistent state
are used. Context storage is 1632 bytes. The CMake root builds the archive but
does not link it into the storage firmware. Test keys exist only in test code.

Initialize a zeroed, naturally aligned `adiantum_ctx` with a 32-byte key.
Use separate destination storage to preserve plaintext; exact in-place use is
also supported. Partial overlap and destination/tweak or context overlap are
rejected. Invalid crypt calls leave output unchanged. Invalid initialization
clears the context. Call `adiantum_clear` when the session ends. Never persist
the context: its representation is private and is not a disk format.

Adiantum provides confidentiality only: a wrong key/tweak decrypts to garbage
without an error. Authentication, key installation validation, reset handling
and storage gating belong to later milestones.

## Pinned provenance and modifications

| Component | Source and revision | License |
| --- | --- | --- |
| Scalar XChaCha12, NH, Poly1305 hash | [google/adiantum](https://github.com/google/adiantum/tree/4feeb5aada81dc2f319996acd4ac95a2a07c99a4/benchmark/src), `4feeb5aada81dc2f319996acd4ac95a2a07c99a4` | MIT; `vendor/LICENSE.Google` |
| AES256 bitsliced key schedule/encrypt/decrypt | [BearSSL](https://www.bearssl.org/gitweb/?p=BearSSL;a=tree;h=7bea48e5e850ab4cafbe68d3765cdaba13a86d6f), `7bea48e5e850ab4cafbe68d3765cdaba13a86d6f` | MIT; `vendor/LICENSE.BearSSL` |
| Official vectors and independent Python reference | Same Google revision, `test_vectors/ours/Adiantum/Adiantum_XChaCha12_32_AES256.json` and `python/` | MIT; `tests/crypto/reference/LICENSE` |
| Reference AES backend (host tests only) | PyCryptodomex 3.23.0, pinned in `tests/crypto/requirements.txt` | BSD/public-domain mix; distributed package license |

No Google `third_party/` or Linux GPL implementation is included. The Google
benchmark AES glue is deliberately excluded because it uses Linux AES.
The new construction glue follows Google's HBSH/Adiantum algorithm; Google
copyright and MIT terms are preserved with the dependency.

`tools/vendor_adiantum.py` reproduces the checked-in primitive adaptations from
the exact two revisions. It strips benchmark/SIMD code and unused Poly1305
key powers; replaces GNU statement expressions with C11; serializes loads and
stores bytewise; supplies a minimal local declarations header; and adds volatile
wipes to explicit ChaCha/AES key and stream scratch arrays. BearSSL AES's
algorithm is unchanged. Google Python files and official vector JSON are copied
unchanged. `vendor/primitives.h` and `adiantum.c` are project-owned integration
code. No download is required for ordinary builds.

Selected source for milestone 3's SHA256, HMAC, HKDF and AES256-GCM is the same
BearSSL revision (`src/hash/sha2small.c`, `src/mac/hmac.c`, `src/kdf/hkdf.c`,
`src/aead/gcm.c`, `src/symcipher/aes_ct_ctr.c`, and
`src/hash/ghash_ctmul32.c`, plus required support). These are a source selection,
not implemented or validated control crypto. Vendor them and run their primitive
vectors in milestone 3 before protocol use. The Windows client library pins
remain milestone 5 work.

## Side channels and resource limits

AES uses BearSSL's table-free bitsliced Boolean implementation, including the
key schedule. Scalar ChaCha/NH/Poly1305 and the glue use fixed arithmetic paths
for a given public length; no secret-indexed lookup tables are introduced.
This is source-level review, not a timing/power/EM certification. Compiler output
and Cortex-M4 multiplier timing still require hardware validation. Dependencies
are pinned for reproducibility, not a promise of upstream support or audit.
Explicit buffers and the context are wiped; complete erasure of compiler spills,
register copies or interrupted execution is not guaranteed.

GCC 14.3.1 `-Os` archive object text totals 6024 bytes; Debug totals 18228 bytes
(before linker deduplication/dead-code removal). No library globals consume
data/BSS. Release `.su` reports `adiantum_init`'s own frame as 1440 bytes and
AES key schedule as 536 bytes, with deeper calls additional. Budget at least
4 KiB stack for initialization plus caller/interrupt headroom pending measured
high-water results; the existing firmware's 1 KiB linker stack reservation is
not sufficient evidence for future integration. Crypt uses small fixed scratch
buffers instead of a full-sector stack copy. Measure combined stack, throughput
and interrupt effects before milestone 4 integration.

## Reproduce validation (PowerShell, repository root)

Put CMake, Ninja and `arm-none-eabi-gcc` on PATH. On this machine their pinned
ST bundles are below `$env:LOCALAPPDATA/stm32cube/bundles/`: CMake
`4.3.1+st.1/bin`, Ninja `1.13.2+st.1/bin`, GCC `14.3.1+st.2/bin`.
Host builds use Visual Studio 2022 C tools, x64 MSVC 19.43.34808.

```powershell
python -m pip install --target build/crypto-python -r tests/crypto/requirements.txt
cmake -S tests/crypto -B build/crypto-host -G 'Visual Studio 17 2022' -A x64
cmake --build build/crypto-host --config Debug
cmake --build build/crypto-host --config Release
$env:PYTHONPATH = 'build/crypto-python'
python tests/crypto/test_adiantum.py build/crypto-host/Debug/adiantum_test.dll
python tests/crypto/test_adiantum.py build/crypto-host/Release/adiantum_test.dll
cmake --preset Debug
cmake --build --preset Debug --clean-first
cmake --preset Release
cmake --build --preset Release --clean-first
arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -Os -ICrypto tests/crypto/target_link.c build/Release/Crypto/libadiantum.a --specs=nosys.specs -o build/crypto-target-link.elf
arm-none-eabi-size build/crypto-target-link.elf build/Debug/Crypto/libadiantum.a build/Release/Crypto/libadiantum.a
```

Each host configuration checks all 180 official encrypt/decrypt vectors,
128 independent sector cases (four keys, eight LBAs, four data patterns),
133 additional independent message/tweak boundaries, in-place and disjoint
buffers, unaligned data, source preservation, output guards, invalid lengths,
NULLs, partial/context/tweak overlap, invalid state and context clearing.
The separate Python implementation uses arbitrary-precision hash arithmetic
and PyCryptodomex AES rather than the C module's primitives. Tests use Python
assertions: run without `-O`.

The link-only smoke ELF references all public operations to catch unresolved
target symbols. It is not a bootable board test and must not be flashed.
Its newlib `nosys` link emits expected unavailable-syscall warnings. Native
memory sanitizers, big-endian execution, MCU execution, stack high-water,
throughput and physical side-channel testing have not been run.
