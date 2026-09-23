@echo off
REM ============================================================================
REM Windows Registry Cleaner - Build to EXE Script
REM
REM What this does:
REM   - Enforces Python 3.11+ (64-bit) - matches the app's requirement
REM   - Checks that pip is available before trying to use it
REM   - Uses "python -m pip" instead of bare "pip", so the pip that runs
REM     always belongs to the same Python that "python" resolves to
REM   - Only checks the network when PyInstaller is actually missing
REM   - Builds the .exe, moves it next to this script, and cleans up
REM     build\, dist\ and the .spec file automatically
REM
REM After a successful build:
REM   - "Windows Registry Cleaner.exe" sits next to this script
REM   - Nothing else is left behind (no build folder, no dist folder, no spec file)
REM ============================================================================

setlocal enabledelayedexpansion

REM Work from the script's own folder, no matter where it was invoked from
pushd "%~dp0"

echo.
echo ========================================
echo Windows Registry Cleaner - Build to EXE
echo ========================================
echo.

REM ----------------------------------------------------------------------------
REM 1. Python presence and version check (3.11+, 64-bit)
REM ----------------------------------------------------------------------------
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed, or not on PATH.
    echo.
    echo         Install Python 3.11 or newer (64-bit) from https://www.python.org/
    echo         During installation, make sure "Add Python to PATH" is checked.
    echo.
    popd
    pause
    exit /b 1
)

set "PYVER="
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set "PYVER=%%v"

if not defined PYVER (
    echo [ERROR] Could not determine the installed Python version.
    echo         "python --version" returned no parsable output.
    echo.
    popd
    pause
    exit /b 1
)

set "PYMAJOR="
set "PYMINOR="
for /f "tokens=1,2 delims=." %%a in ("!PYVER!") do (
    set "PYMAJOR=%%a"
    set "PYMINOR=%%b"
)

echo !PYMAJOR!| findstr /r "^[0-9][0-9]*$" >nul
if errorlevel 1 (
    echo [ERROR] Could not parse Python version from: !PYVER!
    echo.
    popd
    pause
    exit /b 1
)

set "PYVER_OK=0"
if !PYMAJOR! GTR 3 set "PYVER_OK=1"
if !PYMAJOR! EQU 3 if !PYMINOR! GEQ 11 set "PYVER_OK=1"

if "!PYVER_OK!"=="0" (
    echo [ERROR] Python !PYMAJOR!.!PYMINOR! detected, but Python 3.11+ is required.
    echo.
    echo         Upgrade Python from https://www.python.org/ and re-run this script.
    echo.
    popd
    pause
    exit /b 1
)

REM Refuse 32-bit Python on 64-bit Windows (filesystem redirection would
REM produce false "missing file" results in the built app).
set "PY_ARCH="
for /f "tokens=2 delims= " %%a in ('python -c "import struct; print(struct.calcsize('P')*8)" 2^>^&1') do set "PY_ARCH=%%a"
if "!PY_ARCH!"=="32" (
    echo [ERROR] This is 32-bit Python, but the app requires 64-bit Python
    echo         on 64-bit Windows.
    echo.
    echo         On 64-bit Windows, a 32-bit Python would see a redirected
    echo         filesystem (System32 -^> SysWOW64) and could report working
    echo         files as missing. Please install 64-bit Python.
    echo.
    popd
    pause
    exit /b 1
)

echo [INFO] Python !PYMAJOR!.!PYMINOR! detected (meets 3.11+ requirement, !PY_ARCH!-bit)
echo.

REM ----------------------------------------------------------------------------
REM 2. pip availability check
REM ----------------------------------------------------------------------------
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip is not available for this Python installation.
    echo.
    echo         Reinstall Python and make sure "pip" is included, or run:
    echo             python -m ensurepip --upgrade
    echo.
    popd
    pause
    exit /b 1
)
echo [INFO] pip is available
echo.

REM ----------------------------------------------------------------------------
REM 3. PyInstaller check (with on-demand internet check + auto-install)
REM ----------------------------------------------------------------------------
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo [INFO] PyInstaller not found. Checking network connection...
    echo.

    ping -n 1 -w 2000 pypi.org >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Cannot reach pypi.org to install PyInstaller.
        echo.
        echo         Either:
        echo           1. Connect to the internet and re-run this script, or
        echo           2. Install PyInstaller manually and re-run:
        echo                  python -m pip install pyinstaller
        echo.
        popd
        pause
        exit /b 1
    )

    echo [INFO] Installing PyInstaller...
    echo.
    python -m pip install pyinstaller
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to install PyInstaller.
        echo         Check the pip output above for details.
        echo.
        popd
        pause
        exit /b 1
    )

    python -c "import PyInstaller" >nul 2>&1
    if errorlevel 1 (
        echo.
        echo [ERROR] PyInstaller installed, but still can't be imported.
        echo         Your Python environment may be misconfigured.
        echo.
        popd
        pause
        exit /b 1
    )

    echo.
    echo [SUCCESS] PyInstaller installed successfully
    echo.
) else (
    echo [INFO] PyInstaller already installed
    echo.
)

REM ----------------------------------------------------------------------------
REM 4. Source file presence check
REM ----------------------------------------------------------------------------
if not exist "windows_registry_cleaner.py" (
    echo [ERROR] windows_registry_cleaner.py not found in this folder:
    echo         %~dp0
    echo.
    echo         Make sure the script is in the same folder as this batch file.
    echo.
    popd
    pause
    exit /b 1
)
echo [INFO] Script file found: windows_registry_cleaner.py
echo.

REM ----------------------------------------------------------------------------
REM 5. Icon file check (warning only - build still works without it)
REM ----------------------------------------------------------------------------
if not exist "windows_registry_cleaner.ico" (
    echo [WARNING] Icon file 'windows_registry_cleaner.ico' not found.
    echo           The EXE will be built without a custom icon.
    echo.
    set "ICON_PARAM="
    set "ADD_DATA_PARAM="
) else (
    echo [INFO] Icon file found: windows_registry_cleaner.ico
    echo.
    set "ICON_PARAM=--icon=windows_registry_cleaner.ico"
    set "ADD_DATA_PARAM=--add-data=windows_registry_cleaner.ico;."
)

REM ----------------------------------------------------------------------------
REM 6. Clean up any leftovers from a previous build
REM ----------------------------------------------------------------------------
echo [INFO] Cleaning up old build files...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "Windows Registry Cleaner.spec" del /q "Windows Registry Cleaner.spec"
echo [INFO] Cleanup complete
echo.

REM ----------------------------------------------------------------------------
REM 7. Build
REM ----------------------------------------------------------------------------
echo ========================================
echo Starting PyInstaller build process...
echo ========================================
echo.
echo This may take a few minutes...
echo.

pyinstaller ^
    --onefile ^
    --windowed ^
    --name "Windows Registry Cleaner" ^
    %ICON_PARAM% ^
    %ADD_DATA_PARAM% ^
    --clean ^
    --noconfirm ^
    windows_registry_cleaner.py

if errorlevel 1 (
    echo.
    echo ========================================
    echo [ERROR] Build failed!
    echo ========================================
    echo.
    echo Check the PyInstaller output above for details.
    echo.
    popd
    pause
    exit /b 1
)

REM ----------------------------------------------------------------------------
REM 8. Verify the .exe really exists before trying to move it
REM ----------------------------------------------------------------------------
if not exist "dist\Windows Registry Cleaner.exe" (
    echo.
    echo ========================================
    echo [ERROR] Build reported success, but the .exe was not found at:
    echo         dist\Windows Registry Cleaner.exe
    echo ========================================
    echo.
    popd
    pause
    exit /b 1
)

echo.
echo ========================================
echo [SUCCESS] Build completed successfully!
echo ========================================
echo.

REM ----------------------------------------------------------------------------
REM 9. Move the .exe up to the script folder
REM ----------------------------------------------------------------------------
echo [INFO] Moving executable to script folder...
if exist "Windows Registry Cleaner.exe" (
    echo [WARNING] An existing "Windows Registry Cleaner.exe" was found here.
    echo           If it's currently running, close it first.
    echo.
    del /q "Windows Registry Cleaner.exe" >nul 2>&1
)

move /Y "dist\Windows Registry Cleaner.exe" "%~dp0Windows Registry Cleaner.exe" >nul
if errorlevel 1 (
    echo [ERROR] Failed to move the executable into the script folder.
    echo.
    echo         It's still available at:
    echo             %~dp0dist\Windows Registry Cleaner.exe
    echo         You can move it manually.
    echo.
    popd
    pause
    exit /b 1
)

if not exist "%~dp0Windows Registry Cleaner.exe" (
    echo [ERROR] Move reported success, but the .exe isn't at the destination.
    echo.
    popd
    pause
    exit /b 1
)

echo [INFO] Executable moved to:
echo        %~dp0Windows Registry Cleaner.exe
echo.

REM ----------------------------------------------------------------------------
REM 10. Clean up every remaining build artifact
REM ----------------------------------------------------------------------------
echo [INFO] Cleaning up build artifacts...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "Windows Registry Cleaner.spec" del /q "Windows Registry Cleaner.spec"
echo [INFO] Cleanup complete
echo.

REM ----------------------------------------------------------------------------
REM Done
REM ----------------------------------------------------------------------------
echo ========================================
echo Build process finished!
echo ========================================
echo.
echo The executable is ready in this folder:
echo   %~dp0Windows Registry Cleaner.exe
echo.
echo You can now:
echo   1. Run the .exe file to test it
echo   2. Move it to any location you want
echo   3. Create a desktop shortcut
echo.

popd
pause