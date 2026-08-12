import os, sys, shutil, subprocess
from pathlib import Path

print('=' * 60)
print('  ERROR-PANEL Build Process')
print('=' * 60)

try:
    import PyInstaller
except ImportError:
    print('Installing PyInstaller...')
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'], check=True)

for folder in ['build', 'dist']:
    p = Path(folder)
    if p.exists():
        shutil.rmtree(p)
        print('Removed ' + folder)

print('Building executable (2-5 minutes)...')
cmd = [
    sys.executable, '-m', 'PyInstaller',
    '--name', 'ERROR-PANEL',
    '--add-data', 'frontend;frontend',
    '--hidden-import=sqlalchemy.dialects.sqlite',
    '--hidden-import=aiosqlite',
    '--hidden-import=backend.app.main',
    '--noconfirm',
    'backend/app/desktop.py'
]
result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode == 0:
    exe = Path('dist/ERROR-PANEL/ERROR-PANEL.exe')
    if exe.exists():
        size_mb = exe.stat().st_size / (1024 * 1024)
        print('Build successful!')
        print('Executable: ' + str(exe))
        print('Size: ' + str(round(size_mb, 2)) + ' MB')
    else:
        print('Executable not found')
else:
    print('Build failed:')
    print(result.stderr[:500])
