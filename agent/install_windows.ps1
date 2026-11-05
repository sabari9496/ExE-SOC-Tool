# EXE-SOC agent installer for Windows 10/11. Run in an ADMINISTRATOR PowerShell. Creates a visible Scheduled Task "EXE-SOC Agent" (runs at startup as SYSTEM).
#   .\install_windows.ps1 -Server https://soc.example.com -Token <TOKEN> [-CaBundle ca.pem]
#   .\install_windows.ps1 -Uninstall
param([string]$Server, [string]$Token, [string]$CaBundle, [switch]$Uninstall, [switch]$KeepData)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run as Administrator (needed to read the Security event log)." }
$Dest = "$env:ProgramFiles\EXE-SOC-Agent"; $Task = "EXE-SOC Agent"
if ($Uninstall) {
  # P5-07: stop ONLY this agent (the scheduled task and processes running from the install folder), never every pythonw on the host; report failures instead of claiming success.
  Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith("$Dest\", [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2
  $Data = "$env:ProgramData\EXE-SOC-Agent"; $targets = @($Dest); if (-not $KeepData) { $targets += $Data }; $failed = @()
  foreach ($t in $targets) { if (Test-Path $t) { Remove-Item $t -Recurse -Force -ErrorAction SilentlyContinue; if (Test-Path $t) { $failed += $t } } }
  if ($failed.Count -gt 0) { throw "Could not remove: $($failed -join ', '). Close anything using those folders and run the uninstall again." }
  if ($KeepData) { "EXE-SOC agent removed. Credential, queue and baselines were KEPT in $Data (-KeepData). Delete that folder yourself when you no longer need them." } else { "EXE-SOC agent removed." }
  return
}
if (-not $Server -or -not $Token) { throw "usage: .\install_windows.ps1 -Server https://HOST -Token TOKEN [-CaBundle ca.pem]" }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Python 3.9+ is required (https://www.python.org/downloads/, tick 'Add to PATH')." }
New-Item -ItemType Directory -Force $Dest | Out-Null; $Src = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($f in "exe_soc_agent.py","soc_preflight.py","exe_soc_diag.py","requirements.txt") { if (-not (Test-Path "$Src\$f")) { throw "$Src\$f is missing - run the installer from the full agent folder." }; Copy-Item "$Src\$f" $Dest -Force }
Copy-Item "$Src\collectors" $Dest -Recurse -Force
if ($CaBundle) { if (-not (Test-Path $CaBundle)) { throw "CA file not found: $CaBundle (it is created by tools\dev_certs.py in certs\ca.pem)" }; Copy-Item $CaBundle "$Dest\ca.pem" -Force; $CaBundle = "$Dest\ca.pem" }
# Install dir runs code as SYSTEM: only SYSTEM/Administrators may write (a user-writable dir would be a privilege-escalation path). Users: read+execute only.
& icacls $Dest /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null; if ($LASTEXITCODE -ne 0) { throw "Could not restrict permissions on $Dest" }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Python 3 was not found on PATH. Install it first; nothing was enrolled and the token is NOT used." }
python -m venv "$Dest\venv"; if ($LASTEXITCODE -ne 0) { throw "python -m venv failed; nothing was enrolled and the token is NOT used." }
& "$Dest\venv\Scripts\pip.exe" install -q -r "$Dest\requirements.txt"; if ($LASTEXITCODE -ne 0) { throw "pip could not install the dependencies (check network/proxy); nothing was enrolled and the token is NOT used." }
$enrollArgs = @("$Dest\exe_soc_agent.py", "enroll", "--server", $Server); if ($CaBundle) { $enrollArgs += @("--ca-bundle", $CaBundle) }
$env:EXESOC_ENROLL_TOKEN = $Token   # token via environment of this process only (never on the command line / process list)
& "$Dest\venv\Scripts\python.exe" @enrollArgs; Remove-Item Env:\EXESOC_ENROLL_TOKEN -ErrorAction SilentlyContinue; if ($LASTEXITCODE -ne 0) { throw "Enrollment was cancelled or failed; nothing was installed as a service." }
$action = New-ScheduledTaskAction -Execute "$Dest\venv\Scripts\python.exe" -Argument "`"$Dest\exe_soc_agent.py`" run"
Register-ScheduledTask -TaskName $Task -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -User "SYSTEM" -RunLevel Highest -Description "EXE-SOC endpoint agent (security telemetry, outbound HTTPS only)" -Force | Out-Null
Start-ScheduledTask -TaskName $Task
"Installed. Check: Get-ScheduledTask 'EXE-SOC Agent'. Remove: .\install_windows.ps1 -Uninstall"
