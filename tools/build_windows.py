"""Reproduce the recorded Windows package without changing system settings."""
from pathlib import Path
import struct
import subprocess
import sys


def main():
    if sys.platform != 'win32' or sys.version_info[:3] != (3, 13, 1) or struct.calcsize('P') != 8:
        raise SystemExit('Use Windows x64 CPython 3.13.1 for this recorded build.')
    root = Path(__file__).resolve().parents[1]
    def run(args):
        subprocess.run(args, cwd=root, check=True)
    run([sys.executable, '-m', 'venv', 'build/gui-venv'])
    python = str(root / 'build/gui-venv/Scripts/python.exe')
    run([python, '-m', 'pip', 'install', '-r', 'host/build-requirements.txt'])
    run([python, '-m', 'pip', 'check'])
    run([python, 'tools/package_windows.py'])


if __name__ == '__main__':
    main()
