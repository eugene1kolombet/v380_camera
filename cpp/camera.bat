@echo off
chcp 65001 >nul
title V380 camera
set IP=%V380_IP%
set PW=%V380_PASSWORD%
if "%IP%"=="" set /p IP=Camera IP: 
if "%PW%"=="" set /p PW=Camera password: 
set EXE=%~dp0v380.exe
:menu
cls
echo ============== V380 CAMERA ==============
echo  Camera IP: %IP%
echo ---------- Recordings on SD card -------
"%EXE%" --ip %IP% --password %PW% list
echo ----------------------------------------
echo.
set /p N=Segment number to download (Enter=exit): 
if "%N%"=="" goto end
echo.
echo Downloading segment %N% to %~dp0rec_%N%.mp4 ...
"%EXE%" --ip %IP% --password %PW% download --seg %N% --out %~dp0rec_%N%.mp4
echo.
echo Done: %~dp0rec_%N%.mp4
echo.
pause
goto menu
:end
