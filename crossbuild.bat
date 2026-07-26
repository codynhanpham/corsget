@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Build every release target declared by the project.
rem Linux and FreeBSD use cross-rs. Native-only Windows and macOS targets are
rem built only when the current host target matches them.

pushd "%~dp0"
if errorlevel 1 (
    echo error: unable to change to the project directory.
    exit /b 1
)
set "TARGET_DIR=target\cross"
for /f "tokens=2" %%H in ('rustc -vV ^| findstr /b /c:"host:"') do set "HOST_TARGET=%%H"
if not defined HOST_TARGET (
    echo error: unable to determine the Rust host target.
    popd
    exit /b 1
)
set "HOST_TARGET_LISTED="
for %%T in (x86_64-unknown-freebsd armv7-unknown-linux-gnueabihf armv7-unknown-linux-musleabihf aarch64-unknown-linux-gnu aarch64-unknown-linux-musl riscv64gc-unknown-linux-gnu x86_64-unknown-linux-gnu x86_64-unknown-linux-musl x86_64-pc-windows-msvc x86_64-apple-darwin aarch64-apple-darwin) do (
    if /i "%%T"=="%HOST_TARGET%" set "HOST_TARGET_LISTED=1"
)

where cross >nul 2>&1
if errorlevel 1 (
    echo error: cross is required for Linux and FreeBSD targets.
    echo install it with: cargo install cross --git https://github.com/cross-rs/cross
    popd
    exit /b 1
)

call :build_cross x86_64-unknown-freebsd
if errorlevel 1 goto :failed
call :build_cross armv7-unknown-linux-gnueabihf
if errorlevel 1 goto :failed
call :build_cross armv7-unknown-linux-musleabihf
if errorlevel 1 goto :failed
call :build_cross aarch64-unknown-linux-gnu
if errorlevel 1 goto :failed
call :build_cross aarch64-unknown-linux-musl
if errorlevel 1 goto :failed
call :build_cross riscv64gc-unknown-linux-gnu
if errorlevel 1 goto :failed
call :build_cross x86_64-unknown-linux-gnu
if errorlevel 1 goto :failed
call :build_cross x86_64-unknown-linux-musl
if errorlevel 1 goto :failed

call :build_native x86_64-pc-windows-msvc
if errorlevel 1 goto :failed
call :build_native x86_64-apple-darwin
if errorlevel 1 goto :failed
call :build_native aarch64-apple-darwin
if errorlevel 1 goto :failed
if not defined HOST_TARGET_LISTED call :build_host
if errorlevel 1 goto :failed

echo All targets built successfully.
popd
exit /b 0

:build_cross
echo ==^> Building %~1
cross build --locked --release --target "%~1" --target-dir "%TARGET_DIR%"
exit /b %errorlevel%

:build_native
if /i not "%~1"=="%HOST_TARGET%" (
    echo ==^> Skipping %~1 ^(native target; host is %HOST_TARGET%^)
    exit /b 0
)
echo ==^> Building %~1
cargo build --locked --release --target "%~1" --target-dir "%TARGET_DIR%"
exit /b %errorlevel%

:build_host
echo ==^> Building %HOST_TARGET% ^(host target^)
cargo build --locked --release --target "%HOST_TARGET%" --target-dir "%TARGET_DIR%"
exit /b %errorlevel%

:failed
set "EXIT_CODE=%errorlevel%"
echo Build failed with exit code %EXIT_CODE%.
popd
exit /b %EXIT_CODE%
