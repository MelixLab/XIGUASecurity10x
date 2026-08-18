@echo off
setlocal enabledelayedexpansion

set PROJECTROOT=d:\XIGUASecurity10x\antivirus-ui
set TAURIROOT=%PROJECTROOT%\src-tauri
set BUILDDIR=%TAURIROOT%\target\release
set PKGROOT=%TAURIROOT%\target\msix-packaging
set OUTPUTMSIX=%TAURIROOT%\target\XIGUASecurity_10.2.33_x64.msix

echo Cleaning...
if exist "%PKGROOT%" rmdir /s /q "%PKGROOT%"
if exist "%OUTPUTMSIX%" del "%OUTPUTMSIX%"

set APPDIR=%PKGROOT%\XIGUASecurity
mkdir "%APPDIR%\assets"

echo Copying files...
copy "%BUILDDIR%\XIGUASecurity.exe" "%APPDIR%\" >nul
echo   XIGUASecurity.exe

if exist "%BUILDDIR%\engines"    xcopy /e /i /q /y "%BUILDDIR%\engines"    "%APPDIR%\engines\"    >nul
if exist "%BUILDDIR%\rulers"     xcopy /e /i /q /y "%BUILDDIR%\rulers"     "%APPDIR%\rulers\"     >nul
if exist "%BUILDDIR%\extensions" xcopy /e /i /q /y "%BUILDDIR%\extensions" "%APPDIR%\extensions\" >nul

for %%f in (sandbox-monitor.html intercept-alert.html popup-prompt.html suspicious-intercept.html threat-alert.html tray-menu.html timeline.html edr-alert.html edr-behavior-chain.html file-protection-alert.html) do (
  if exist "%PROJECTROOT%\%%f" copy "%PROJECTROOT%\%%f" "%APPDIR%\" >nul
)

if exist "%PROJECTROOT%\dist" xcopy /e /i /q /y "%PROJECTROOT%\dist" "%APPDIR%\dist\" >nul

if exist "%TAURIROOT%\icons\StoreLogo_1080x1080.png" copy "%TAURIROOT%\icons\StoreLogo_1080x1080.png" "%APPDIR%\assets\StoreLogo.png" >nul
if exist "%TAURIROOT%\icons\Square44x44Logo.png"    copy "%TAURIROOT%\icons\Square44x44Logo.png"    "%APPDIR%\assets\" >nul

REM Use the pre-written AppxManifest.xml
copy "%TAURIROOT%\AppxManifest.xml" "%APPDIR%\" >nul
echo   AppxManifest.xml

echo Running MakeAppx.exe...
"%PROGRAMFILES(X86)%\Windows Kits\10\bin\10.0.26100.0\x64\makeappx.exe" pack /v /o /d "%PKGROOT%\XIGUASecurity" /p "%OUTPUTMSIX%"

if errorlevel 1 (
  echo MakeAppx.exe failed.
  exit /b 1
)

echo Done.
echo MSIX: %OUTPUTMSIX%
for %%f in ("%OUTPUTMSIX%") do echo Size: %%~zf bytes
