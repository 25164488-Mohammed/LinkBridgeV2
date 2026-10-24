@echo off
chcp 65001 >nul
title LinkBridge — Windows One-Click Builder & Launcher
echo ========================================================
echo   LinkBridge — بناء وتشغيل النسخة التنفيذية المستقلة (.exe)
echo   عمل محمد البكير
echo ========================================================

if exist "dist\LinkBridge-Windows.exe" (
    echo Starting LinkBridge-Windows.exe ...
    start "" "dist\LinkBridge-Windows.exe"
    exit /b 0
)

where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] يرجى تثبيت Python 3.11 من متجر Microsoft Store أو python.org لبناء ملف .exe لأول مرة فقط.
    pause
    exit /b 1
)

echo [1/2] جاري تثبيت الحزم المطلوبة وبناء ملف LinkBridge-Windows.exe المستقل...
python -m pip install --upgrade pip
python -m pip install -r windows\requirements.txt
pyinstaller --noconfirm --clean --onefile --windowed --name "LinkBridge-Windows" --paths "." windows\app.py

echo [2/2] اكتمل بناء الملف التنفيذي المستقل: dist\LinkBridge-Windows.exe
start "" "dist\LinkBridge-Windows.exe"
