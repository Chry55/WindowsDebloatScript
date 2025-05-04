@echo off
cd C:/WindowsDebloatScript/
OOSU10.exe ooshutup10.cfg /quiet
set "psScript=%~dp0Windows debloat script.ps1"
powershell -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -File ""%psScript%""' -Verb RunAs}";
