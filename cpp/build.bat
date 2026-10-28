@echo off
rem Сборка v380.exe компилятором MSVC.
rem Запускать из обычной cmd — скрипт сам подхватит окружение компилятора.
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
cl /nologo /EHsc /O2 /W3 v380.cpp
if exist v380.exe (echo. & echo Готово: v380.exe) else (echo Ошибка сборки)
endlocal
