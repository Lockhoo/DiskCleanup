@echo off
setlocal
cd /d "%~dp0独立版\DiskCleanup-独立版"
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo 找不到 csc.exe：需要 Windows 自带的 .NET Framework 4.x
  pause
  exit /b 1
)
"%CSC%" /nologo /target:winexe /optimize+ /win32manifest:app.manifest /out:DiskCleanup.exe ^
  /r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll Program.cs
if errorlevel 1 (
  echo 编译失败
  pause
  exit /b 1
)
echo 编译完成：%cd%\DiskCleanup.exe
pause
