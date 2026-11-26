# Anti-forensic capabilities

Added 2026-11-11. These are defensive protections for the drive's user:
ways to make the owner's data unrecoverable on demand or under coercion. They do not
change the base threat model in [README.md](README.md#security-model-and-limitations); they add
erasure options on top of it. Status: **software implemented and logic-tested; hardware
validation pending**.

There are three mechanisms.

## 1. Crypto-erase (DESTROY) — instant, for encrypted volumes

**What it does.** In an authenticated session the board overwrites both on-card header
copies (physical sectors 0..15) and then erases the credential journal (flash sectors
6/7), returning the device to the virgin state.

**Why it is strong.** The 256-bit data key is random and is stored **only** inside the
AES-256-GCM-wrapped-key field of the header (`Storage/FORMAT.md`, offset 128). It is
never written in the clear and is not derivable from the password or file alone — the
wrap binds it. Zeroing the header destroys both copies of the wrapped key, so the data
key is gone forever and the Adiantum-encrypted sectors can never be decrypted again,
even by someone holding the correct authentication file **and** password. This is
textbook cryptographic erasure: destroy the key, not the (large) ciphertext.

**Ordering is fail-safe.** The header is zeroed and verified *first*. Only if that
succeeds is the credential journal erased. An SD failure therefore returns `BP_IO`
with credentials intact, so the owner can retry rather than being left with a
half-wiped, unusable device. (Logic-tested: `tests/antiforensic/test_destroy.c`,
scenario C.)

**Plaintext (mode 1) caveat.** For an auth-only volume there is no key to destroy.
DESTROY still removes the header and credentials (the drive can no longer be used
through the board), but the plaintext data physically remains on the card and is
readable with another reader. To erase plaintext data, use the full secure-erase (§2).

**Protocol.** `BEGIN` operation `3`, then protected opcode `8 DESTROY` (empty body),
only while media is unmounted. Host: authenticate with `operation=3`, then
`volume.destroy(client)`. Exposed as `bpctl.py destroy` and the GUI "Erase drive
(crypto-erase)…" button.

## 2. Full secure-erase — overwrite, for plaintext data or belt-and-suspenders

Fast setup (format 2) only invalidates partition metadata; untouched sectors keep old
data (`Storage/FORMAT.md`, "Fast setup's changed guarantees"). The full secure-erase
is the existing **format-1 full initialization** exposed as a user choice: every
logical sector is written (encrypted-zeros in mode 2, zeros in mode 1), so no old
plaintext survives in the data region. It is slow — on a 64 GB card at the measured
~10k sectors/min it takes hours — so it is opt-in and labelled as such. For encrypted
volumes, crypto-erase (§1) is the practical instant wipe; full overwrite is for
plaintext volumes or extra assurance.

Exposed as `bpctl.py setup --secure-erase` and the GUI "Full secure-erase" method.

## 3. Duress (decoy) password — erase under coercion

An optional second credential that **triggers the crypto-erase instead of unlocking**,
while showing an ordinary "wrong password" error so the coercer does not realise.

**Design (host-side).** The board never sees the password — the host unwraps the data
key and sends only the key. So duress is enforced where the password lives: the host.
The authentication file (version 2) may carry an Argon2id verifier of the decoy
password (`duress.salt`, `duress.verifier`, `duress.kdf`, parameters 64 MiB / 3 / 1 to
match the data KDF). At unlock the host tries the real key unwrap; **only if that
fails** does it check the decoy verifier (so a real unlock is never mistaken for
duress). On a decoy match it runs the DESTROY flow and raises an error whose text is
byte-identical to a normal wrong-password failure.

**Scope and limits (be honest with users).**
- It protects the realistic case: the owner is compelled to unlock at the utility and
  types the decoy instead of the real password.
- It does **not** stop an attacker who has the authentication file and drives the raw
  protocol themselves — they would simply not type the decoy. Duress is a host-GUI
  behaviour, not a board-enforced property.
- The verifier sits in the file; someone who steals the file could, in principle,
  crack the Argon2id verifier offline and learn the decoy to avoid it. Argon2id makes
  this expensive, but it is not impossible. (A file thief still cannot unlock without
  the real password.)
- The decoy must differ from the real password; the GUI/CLI enforce this.

Set/clear it with `bpctl.py duress [--clear]`, the GUI "Decoy password…" button, or the
optional decoy field during encrypted setup. It is a pure local-file update; the board
is never contacted.

## What none of this changes

Adiantum still provides confidentiality, not sector authentication or rollback
protection. Full-sector initialization is not a guarantee about remapped/worn SD flash
cells. The USB identity is still the development ST VID/PID. All limitations listed in
[README.md](README.md#security-model-and-limitations) remain. Crypto-erase and secure-erase are irreversible by
design and require explicit confirmation.
