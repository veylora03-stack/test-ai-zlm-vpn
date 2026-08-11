# ERROR-PANEL Build Script — PyInstaller packaging
# Run from the repo root directory on Windows

# Install PyInstaller if missing
if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    pip install pyinstaller
}

# Build single-file executable
pyinstaller --onefile `
    --name ERROR `
    --add-data "..\frontend;frontend" `
    backend/app/desktop.py

Write-Host ""
Write-Host "Build complete: dist\ERROR.exe" -ForegroundColor Green
Write-Host "Copy dist\ERROR.exe to any Windows machine and run it." -ForegroundColor Cyan
