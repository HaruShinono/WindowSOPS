@echo off
setlocal EnableExtensions EnableDelayedExpansion
title WindowSOPS (written by HaruShinono)
color 0A

REM [CONFIG & PATHS]
set "PS=powershell.exe -NoProfile -ExecutionPolicy Bypass"
set "LOG=%~dp0WS_Report.txt"
REM -- Fallback to Temp if current folder is not writable --
(> "%LOG%" echo Init) >nul 2>&1 || set "LOG=%TEMP%\WS_Report.txt"
if not exist "%LOG%" type nul > "%LOG%"

REM -- Pass Log path to PowerShell --
set "LOGFILE=%LOG%"
set "TMPFILE=%TEMP%\ws_tmp_out.txt"

REM [ADMIN CHECK]
net session >nul 2>&1 || (color 0C & echo [!] ADMIN RIGHTS REQUIRED & pause & exit /b)

REM [HEADER]
call :LOG_HEADER "WindowSOPS Started"

:MENU
cls
echo ================================================
echo        WindowSOPS v3.3 (by HaruShinono)
echo ================================================
echo [1] Deep System Audit (HW, IP, Disk)
echo [2] Security Check (Firewall, AV, UAC)
echo [3] Process Analysis (Suspicious, High RAM)
echo [4] Network Analysis (Connections, Routes)
echo [5] Advanced Port Scanner
echo [6] User and Privilege Audit
echo [7] Event Log Analysis (Logins, Creations)
echo [8] Integrity and Update Status
echo [9] Open Report
echo [G] My GitHub
echo [Q] Exit
echo ================================================
set "OPT="
set /p OPT=Select: 

if "%OPT%"=="1" goto AUDIT
if "%OPT%"=="2" goto SECURITY
if "%OPT%"=="3" goto PROCESS
if "%OPT%"=="4" goto NETWORK
if "%OPT%"=="5" goto PORTS_MENU
if "%OPT%"=="6" goto USERS
if "%OPT%"=="7" goto EVENTS
if "%OPT%"=="8" goto INTEGRITY
if "%OPT%"=="9" goto OPENLOG
if /i "%OPT%"=="G" goto GIT
if "%OPT%"=="0" goto END
goto MENU

REM ================= MODULES =================
REM NOTE: Commands are now executed directly to avoid quoting errors.
REM Output is piped to TMPFILE, then TEE is called to display & log it.

:AUDIT
cls
call :SECTION_START "System Audit"
echo [*] Gathering OS Info...
systeminfo | findstr /i "OS Name Version Manufacturer Model Type" > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] Disk Space Status...
wmic logicaldisk get size,freespace,caption > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] IP Configuration...
ipconfig /all | findstr /i "Description IPv4 Physical" > "%TMPFILE%" 2>&1
call :TEE
call :SECTION_END
goto WAIT

:SECURITY
cls
call :SECTION_START "Security Check"
echo [*] Windows Defender Service...
sc query windefend | findstr "STATE" > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] Defender Real-time Status...
%PS% -Command "Get-MpComputerStatus | Select AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled" > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] Firewall Profiles...
netsh advfirewall show allprofiles | findstr "Profile State" > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] Checking UAC Level...
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA > "%TMPFILE%" 2>&1
call :TEE
call :SECTION_END
goto WAIT

:PROCESS
cls
call :SECTION_START "Process Analysis"
echo [*] Searching for Risky Binaries (LOLBins)...
tasklist /v | findstr /i "powershell cmd wscript cscript rundll32 regsvr32 mshta bitsadmin certutil" > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] Top 5 High Memory Consumers...
%PS% -Command "Get-Process | Sort-Object NPM -Descending | Select-Object -First 5 Name, Id, NPM, Path | Format-Table -AutoSize" > "%TMPFILE%" 2>&1
call :TEE
call :SECTION_END
goto WAIT

:NETWORK
cls
call :SECTION_START "Network Analysis"
echo [*] Active Established Connections...
netstat -ano | findstr "ESTABLISHED" > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] DNS Cache (Top 10)...
%PS% -Command "Get-DnsClientCache | Select-Object -First 10 Entry, Name, Data" > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] Routing Table (External)...
route print -4 | findstr "0.0.0.0" > "%TMPFILE%" 2>&1
call :TEE
call :SECTION_END
goto WAIT

:PORTS_MENU
cls
echo --- Port Scanner Module ---
echo [1] Quick Scan (Top 20)
echo [2] Custom Range
echo [3] Localhost Check
echo [4] Back
set "P_OPT="
set /p P_OPT=Select: 
if "%P_OPT%"=="1" set "CMD=$p=@(21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5900,8080,8443,1433);" & goto P_INPUT
if "%P_OPT%"=="2" goto P_CUSTOM
if "%P_OPT%"=="3" set "TGT=127.0.0.1" & set "CMD=$p=@(21,22,23,25,53,80,135,139,443,445,3389,8080);" & goto P_RUN
if "%P_OPT%"=="4" goto MENU
goto PORTS_MENU

:P_CUSTOM
set "TGT="
set /p TGT=Target IP: 
set "S_P="
set /p S_P=Start Port: 
set "E_P="
set /p E_P=End Port: 
set "CMD=$p=%S_P%..%E_P%;"
goto P_RUN

:P_INPUT
set "TGT="
set /p TGT=Target IP: 
if not defined TGT goto PORTS_MENU

:P_RUN
cls
call :SECTION_START "Port Scan: %TGT%"
echo [Scanning] Please wait (Green=Open, Gray=Closed)...
REM -- PS handles logging internally here to support colors --
%PS% -Command "$t='%TGT%'; %CMD% $log=$env:LOGFILE; foreach($x in $p){ Try{ $c=New-Object Net.Sockets.TcpClient; $ar=$c.BeginConnect($t,$x,$null,$null); $w=$ar.AsyncWaitHandle.WaitOne(150); if($w -and $c.Connected){ $c.EndConnect($ar); $msg=\"[+] Port $x : OPEN\"; Write-Host $msg -ForegroundColor Green; Add-Content $log $msg } else { if($p.Count -lt 50){ Write-Host \"[-] Port $x : Closed\" -ForegroundColor DarkGray } }; $c.Close() } Catch { if($p.Count -lt 50){ Write-Host \"[!] Port $x : Error\" -ForegroundColor DarkGray } } }"
call :SECTION_END
goto WAIT

:USERS
cls
call :SECTION_START "User Audit"
echo [*] Local Administrators...
net localgroup administrators > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] All Local Users...
wmic useraccount get name,disabled,passwordrequired,lockout > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] Guest Account Status...
net user Guest | findstr "Active" > "%TMPFILE%" 2>&1
call :TEE
call :SECTION_END
goto WAIT

:EVENTS
cls
call :SECTION_START "Event Log Analysis"
echo [*] Last 5 Failed Logins (Event 4625)...
REM -- Direct command fixes the quoting issue --
wevtutil qe Security /q:"*[System[EventID=4625]]" /c:5 /f:text > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] New User Creations (Event 4720)...
wevtutil qe Security /q:"*[System[EventID=4720]]" /c:5 /f:text > "%TMPFILE%" 2>&1
call :TEE
call :SECTION_END
goto WAIT

:INTEGRITY
cls
call :SECTION_START "Integrity and Updates"
echo [*] Pending Reboot Status...
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v PendingFileRenameOperations > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] Last 10 Installed Hotfixes...
%PS% -Command "Get-HotFix | Sort InstalledOn -Desc | Select -First 10 Description,HotFixID,InstalledOn" > "%TMPFILE%" 2>&1
call :TEE

echo.
echo [*] Running SFC (System File Checker)...
echo     (Output sent directly to screen due to complexity)
sfc /scannow
echo [Info] SFC Check finished at %time% >> "%LOG%"
call :SECTION_END
goto WAIT

REM ================= HELPERS =================

:TEE
REM -- Prints TEMP file to Screen AND Log, then deletes it --
if exist "%TMPFILE%" (
    type "%TMPFILE%"
    type "%TMPFILE%" >> "%LOG%"
    del /q "%TMPFILE%"
) else (
    echo [!] No output or command failed.
)
exit /b

:LOG_HEADER
echo. >>"%LOG%"
echo ========================================== >>"%LOG%"
echo   %~1 [%date% %time%] >>"%LOG%"
echo ========================================== >>"%LOG%"
exit /b

:SECTION_START
call :LOG_HEADER "%~1"
echo ------------------------------------------
echo  RUNNING: %~1
echo ------------------------------------------
exit /b

:SECTION_END
echo.
echo ------------------------------------------
echo  COMPLETED.
echo ------------------------------------------
echo. >>"%LOG%"
exit /b

:WAIT
echo.
echo [Press Enter to return to Menu]
pause >nul
goto MENU

:OPENLOG
start "" "%LOG%"
goto MENU

:GIT
start https://github.com/HaruShinono
goto MENU

:END
call :LOG_HEADER "WindowSOPS Stopped"
echo Report saved to: %LOG%
timeout /t 2 >nul
exit /b
