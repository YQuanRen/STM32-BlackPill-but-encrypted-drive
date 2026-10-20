# Build on Windows with the pinned environment; one-folder, no console, no UPX.
from pathlib import Path
from PyInstaller.utils.hooks import copy_metadata

source = Path(SPECPATH)
metadata = []
for package in ('cryptography', 'argon2-cffi', 'argon2-cffi-bindings', 'cffi', 'hidapi'):
    metadata += copy_metadata(package)
a = Analysis([str(source / 'gui.py')], pathex=[str(source)],
             datas=metadata, hiddenimports=['hid', '_cffi_backend', 'smoke'],
             excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='BlackPillDrive',
          debug=False, strip=False, upx=False, console=False,
          disable_windowed_traceback=True)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='BlackPillDrive')
