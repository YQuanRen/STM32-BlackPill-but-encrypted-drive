# BlackPill Drive for Windows

Development build: software-tested; physical device validation is pending.
Fast setup is the default as of 2026-10-21. Update firmware AND this utility.
Completed old volumes remain readable. If old full-card setup was interrupted,
keep its authentication file and explicitly restart setup after updating.
Intended platform: Windows 10/11 x64. Packaged runtime was tested on the development
Windows machine, not a fresh Windows installation. There is no Mac/Linux package.

## Start

Extract the entire ZIP to a local folder and run `BlackPillDrive.exe`. Keep the
`_internal` folder beside it; do not copy only the EXE. Python is bundled, so a
separate Python installation is not needed to run this package. No installer,
administrator elevation or driver changes are performed by the utility. Actual
Windows HID permissions/driver binding have not yet been verified on hardware.

This development executable is unsigned. Windows may show an unknown publisher
or SmartScreen warning. Verify the source and supplied ZIP SHA256 with
`Get-FileHash .\BlackPillDrive-windows-x64.zip -Algorithm SHA256`; do not disable
security protection to run a package you do not trust. Release signing and
fresh-machine acceptance are still pending.

## First use

1. Connect the pre-flashed drive and click Refresh. If multiple drives appear,
   explicitly select the full device ID you intend to configure.
2. A new device opens Setup. Choose **File + password** for encrypted SD data,
   or **File only** for plaintext SD data with the board's access gate.
3. Use **Save new file** to choose a location on another drive. The file is saved
   when you click **Inspect card and continue**, before enrollment. Keep it and
   make a separate backup. If retrying interrupted enrollment, use **Choose file**
   to select the file already saved. Existing files are never overwritten.
4. Inspect the displayed device ID, card ID, byte capacity and chosen mode. Back up
   existing card data. For encrypted mode enter and confirm a password.
5. Type the exact displayed `ERASE ...` phrase and click **Replace volume (fast
   setup)**. This replaces the volume and prepares only partition metadata and
   authenticated headers. It does NOT erase old data in untouched sectors.
   Keep the drive connected until progress completes.
6. After initialization/unlock, use Windows Disk Management to create a partition
   and select **Quick Format**, then restore files. Do this through the unlocked
   Black Pill, not a separate reader. Confirm the right disk there too.
   The utility does not partition or format Windows drives.

Flashing alone does not encrypt existing data. Encryption starts with encrypted
setup; metadata remains visible on a removed card. Fast setup is not sanitization
or in-place conversion: untouched old plaintext may remain recoverable. Unwritten
encrypted sectors decrypt to arbitrary bytes, not guaranteed zeros. Create and
quick-format a fresh volume before use. In file-only mode a separate
card reader bypasses the board's gate. Adiantum encrypts sectors but does not
authenticate their contents or prevent rollback. Initialization is not guaranteed
sanitization of remapped flash cells.

## Reconnect and unlock

Select the drive and its authentication file. Enter the password if encrypted,
then click **Unlock drive**. Open it in Explorer after success. Safely eject in
Windows before unplugging. Reconnecting locks it again. There is no live-lock
button or automatic unlock.

Lost file or password means lost encrypted-data access; no recovery is available.
Keep both private. The authentication file is a copyable credential, not proof of
a particular computer or program. Python cannot guarantee erasure of all secret
copies from process memory.

## Reinitialization and errors

To change mode, back up the data, safely eject/unplug/reconnect, choose the existing
authentication file, then click **Reinitialize / change mode**. Setup replaces the
volume again, without erasing all old data, and requires the exact confirmation
phrase. Changing the file's saved
mode does not change the board's authenticated policy.

- Wrong password/file: media remains locked. Select the original file and retry.
- Missing/invalid header: do not assume the card is blank. Check the card and
  backups. Interrupted setup needs explicit volume replacement and quick-formatting.
- Disconnect or SD failure: reconnect and refresh. Keep the saved authentication
  file even if a request timed out; do not create a replacement for an enrolled drive.
- Device/card changed: refresh, select the intended device and inspect again.
- Already unlocked/wrong state: safely eject and reconnect before setup or a new
  authentication session. Closing the utility does not lock a mounted drive.
- No drives/access error: check the USB data cable, firmware and Windows device
  status; close other BlackPill utilities. No automatic driver replacement occurs.
- Credential flash fault: reconnect; a persistent fault requires offline service.
  Do not mass-erase firmware flash if you need to preserve its credentials.

The window remains responsive during work and displays initialization progress.
Closing is blocked while an operation is in progress. Unplugging or killing the
process can interrupt initialization; keep the file and explicitly restart setup.

See `BUILD.json` for bundled versions and `licenses/` for dependency notices.
Hardware validation, throughput and stack measurements are not implied by a
successful software self-test.
