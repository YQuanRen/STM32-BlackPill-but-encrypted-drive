# Windows and board acceptance record

Status on 2026-10-21: pending physical validation. No connected card was erased,
no board was flashed, and no physical HID enumeration was run during milestone 5.
The packaged smoke check uses hidden Tk widgets and native crypto/HID imports
without opening a device. It is not a fresh-machine or board test.

Use a specifically designated disposable/backed-up card for destructive checks.
Record firmware hash, package SHA256, Windows version/build, board revision, SD
model/CID/capacity, cable and USB controller for each run. Preserve journal sectors
6/7 during normal firmware updates. Never use a production volume for power cuts.

| Acceptance check | Required evidence | Result |
| --- | --- | --- |
| Fresh Windows 10/11 x64, no Python | ZIP extraction, launch, HID/MSC binding and normal-user permissions | Pending |
| New auth-only setup | File saved outside drive, exact identity/card confirmation, progress, Windows format | Pending |
| New encrypted setup | Password confirmation, bounded metadata setup, QUICK-format through the Pill and normal Explorer access | Pending |
| Fast setup on reused MBR/GPT cards | Disk Management sees an unformatted disk; new partition/quick-format works; untouched old plaintext may remain | Pending |
| Safe eject/reconnect in both modes | Locked before credentials, correct unlock, media insertion without replug | Pending |
| Wrong file/password | No usable MSC media and actionable GUI error | Pending |
| Several connected boards | Deliberate selection; other cards and credential files unchanged | Pending |
| File integrity | SHA256 before copy and after eject/reconnect/unlock; small/large files and capacity boundaries | Pending |
| Independent SD reader | Auth-only plaintext at physical LBA+16; encrypted mode ciphertext, no plaintext filesystem | Pending |
| Card removal/swap and USB reset/suspend | Gate/key reset as specified; suspend preserves mounted media; errors reported | Pending |
| SD/flash power interruption | Fault/locked or complete valid transaction, explicit restart; no old-mode fallback | Pending |
| SD timeout behavior | Timeouts return with SysTick priority 0 / USB priority 1, no interrupt deadlock | Pending |
| Performance | Auth-only vs encrypted read/write MiB/s; total initialization duration for stated capacity | Pending |
| Resource usage | MCU stack high-water in init/crypto/USB nesting, heap/static RAM, flash fit | Pending |

For integrity tests, use `Get-FileHash -Algorithm SHA256` on the source and copied
file after safe eject/reconnect/unlock. Record hashes and timings, not credentials,
passwords, root secrets or data keys. Throughput measurements must distinguish OS
cache effects from sustained media writes; record file size, method and completion
flush/eject time. Do not claim measured MCU throughput from native simulation.

Fast setup was explicitly authorized on 2026-10-21 for new v2 volumes; do not claim
whole-card verification or erasure. Retain metadata readback checks, KDF strength
and encryption. Update HANDOFF.md with actual evidence and any failures. A full
Windows format still writes every sector; use Quick Format for this workflow.
