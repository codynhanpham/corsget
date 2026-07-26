@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Build every release target declared by the project.
rem Linux and FreeBSD use cross-rs. Windows and macOS use cargo because
rem cross-rs does not provide default images for those native targets.

pushd "%~dp0"
if errorlevel 1 (
    echo error: unable to change to the project directory.
    exit /b 1
)
set "TARGET_DIR=target\cross"

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
call :build_cross riscv64gc-unknown-linux-musl
if errorlevel 1 goto :failed

call :build_cargo x86_64-pc-windows-msvc
if errorlevel 1 goto :failed
call :build_cargo x86_64-apple-darwin
if errorlevel 1 goto :failed

echo All targets built successfully.
popd
exit /b 0

:build_cross
echo ==^> Building %~1
cross build --locked --release --target "%~1" --target-dir "%TARGET_DIR%"
exit /b %errorlevel%

:build_cargo
echo ==^> Building %~1
cargo build --locked --release --target "%~1" --target-dir "%TARGET_DIR%"
exit /b %errorlevel%

:failed
set "EXIT_CODE=%errorlevel%"
echo Build failed with exit code %EXIT_CODE%.
popd
exit /b %EXIT_CODE%
