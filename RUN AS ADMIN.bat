@echo off
setlocal

pushd "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) { Start-Process -FilePath '%~f0' -Verb RunAs; exit 1 }"
if %ERRORLEVEL% NEQ 0 (
    popd
    exit /b
)

set "scriptDir=%~dp0"
set "exePath=%scriptDir%OOSU10.exe"
set "cfgPath=%scriptDir%ooshutup10.cfg"
set "psScript=%scriptDir%Windows debloat script.ps1"

"%exePath%" "%cfgPath%" /quiet

powershell -NoProfile -ExecutionPolicy Bypass -File "%psScript%"

popd
endlocal
