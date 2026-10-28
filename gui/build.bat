@echo off
rem Сборка v380gui.exe (оконное приложение) компилятором MSVC.
setlocal
cd /d %~dp0
set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist %VSWHERE% for /f "usebackq delims=" %%i in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSDIR=%%i
set VCVARS="%VSDIR%\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% (
  echo Не найдена Visual Studio с компонентом C++ ^(Desktop development with C++^).
  exit /b 1
)
call %VCVARS% >nul
cl /nologo /utf-8 /EHsc /O2 /DUNICODE /D_UNICODE v380gui.cpp /link /SUBSYSTEM:WINDOWS
if exist v380gui.exe (echo. & echo Готово: v380gui.exe) else (echo Ошибка сборки)
endlocal
