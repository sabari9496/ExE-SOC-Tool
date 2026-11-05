@echo off
rem Turns on the Windows audit settings that EXE-SOC needs to see logins, accounts, groups, processes, services, tasks and PowerShell activity.
rem Right-click and "Run as administrator". Uses English audit names (on other languages use the localized names).
net session >nul 2>&1 || (echo Please run this file as Administrator. & pause & exit /b 1)
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
auditpol /set /subcategory:"File Share" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
wevtutil sl Security /ms:209715200
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /e:true
echo.
echo Done. Process creation (with command line), logins, accounts, groups, tasks and PowerShell script blocks are now logged.
echo For the most complete process / network / file activity also install Sysmon (Microsoft, free); EXE-SOC reads its log automatically.
pause
