#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 11 optimization builder with embedded Defender Gaming Halt.

.DESCRIPTION
    Builds an optimized Windows 11 ISO and injects DefenderHalt.ps1 directly
    into the image. On first login after install, a scheduled task automatically
    places two desktop shortcuts:

        Game Mode ON   — halts Defender (WdFilter + services + process suspend)
        Game Mode OFF  — fully restores Defender

    The script lives at  C:\GameMode\DefenderHalt.ps1  on the installed system.
    The shortcuts run hidden/elevated so no terminal window flashes.

    Build optimizations:
      * Single DISM mount per WIM
      * No WIM recompression (None compression on ESD export)
      * Native .NET registry API — zero reg.exe spawns during hive edits
      * Robocopy with /J (unbuffered NVMe I/O)
      * Move instead of copy for WIM placement (same-volume rename)
      * Feature list pre-queried once, no per-feature DISM launches
      * Parallel scheduled-task folder deletion
      * oscdimg without -o (no dedup scan)
      * Async scratch cleanup

.PARAMETER ISO
    Drive letter of mounted Windows 11 ISO (e.g. D).

.PARAMETER SCRATCH
    Drive letter for scratch/build work. Put on fastest NVMe.
    Defaults to the drive containing this script.

.NOTES
    Requires: Windows ADK (oscdimg.exe), PowerShell 5.1+, Admin rights.

    FIRST-TIME SETUP ON INSTALLED SYSTEM:
      After Windows installs and you log in for the first time, the two
      Game Mode shortcuts will appear on your Desktop automatically.
      Before using "Game Mode ON", go to:
        Windows Security -> Virus & threat protection -> Manage settings
        -> Tamper Protection -> OFF
      You only need to do this once.
#>

param (
    [ValidatePattern('^[c-zC-Z]$')]
    [string]$ISO,

    [ValidatePattern('^[c-zC-Z]$')]
    [string]$SCRATCH
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Boost build-process priority
$p = [System.Diagnostics.Process]::GetCurrentProcess()
$p.PriorityClass = 'High'
[System.Threading.Thread]::CurrentThread.Priority = 'Highest'

#region ─── PATHS ─────────────────────────────────────────────────────────────

$ScratchDisk = if ($SCRATCH) { "${SCRATCH}:" } else { $PSScriptRoot.TrimEnd('\') }
$BuildRoot   = "$ScratchDisk\Win11Opt"
$MountDir    = "$ScratchDisk\Mount"
$TempDir     = "$ScratchDisk\Temp"
$OutputISO   = "$PSScriptRoot\Windows11_Optimized.iso"
$Oscdimg     = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe'

[void][System.IO.Directory]::CreateDirectory($BuildRoot)
[void][System.IO.Directory]::CreateDirectory($MountDir)
[void][System.IO.Directory]::CreateDirectory($TempDir)

#endregion

#region ─── LOGGING ───────────────────────────────────────────────────────────

function Write-Step {
    param([string]$Msg, [string]$Color = 'Cyan')
    Write-Host "[$([datetime]::Now.ToString('HH:mm:ss'))] $Msg" -ForegroundColor $Color
}
function Write-Ok   { param([string]$M) Write-Host "  OK  $M" -ForegroundColor Green    }
function Write-Skip { param([string]$M) Write-Host " SKIP $M" -ForegroundColor DarkGray }
function Write-Warn { param([string]$M) Write-Host " WARN $M" -ForegroundColor Yellow   }

#endregion

#region ─── OFFLINE REGISTRY (pure .NET) ──────────────────────────────────────

$script:OpenHives = @{}

function Open-OfflineHive {
    param([string]$HivePath, [string]$Alias)
    $r = & reg load "HKLM\$Alias" $HivePath 2>&1
    if ($LASTEXITCODE -ne 0) { throw "reg load failed for $Alias : $r" }
    $script:OpenHives[$Alias] = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Alias, $true)
}

function Close-OfflineHive {
    param([string]$Alias)
    if ($script:OpenHives.ContainsKey($Alias)) {
        $script:OpenHives[$Alias].Close()
        $script:OpenHives[$Alias].Dispose()
        $script:OpenHives.Remove($Alias)
    }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    $retries = 0
    do {
        Start-Sleep -Milliseconds 200
        $null = & reg unload "HKLM\$Alias" 2>&1
        $retries++
    } while ($LASTEXITCODE -ne 0 -and $retries -lt 10)
    if ($LASTEXITCODE -ne 0) { Write-Warn "reg unload $Alias may not have fully released" }
}

function Open-Or-CreateSubKey {
    # Walks every segment of a backslash-separated path, opening or creating
    # each level with explicit ReadWriteSubTree permission.
    # CreateSubKey on an offline hive fails for deep paths when any ancestor
    # does not yet exist — this avoids that by stepping one level at a time.
    param([Microsoft.Win32.RegistryKey]$Root, [string]$SubKeyPath)
    $current = $Root
    foreach ($segment in $SubKeyPath.Split('\')) {
        $next = $current.OpenSubKey(
            $segment,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
        )
        if ($null -eq $next) {
            $next = $current.CreateSubKey(
                $segment,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
            )
        }
        if ($current -ne $Root) { $current.Close() }
        $current = $next
    }
    return $current   # caller must .Close() the returned key
}

function Set-RegVal {
    param(
        [string]$HiveAlias,
        [string]$SubKey,
        [string]$Name,
        [Microsoft.Win32.RegistryValueKind]$Kind,
        [object]$Value
    )
    $base = $script:OpenHives[$HiveAlias]
    $key  = Open-Or-CreateSubKey $base $SubKey
    $key.SetValue($Name, $Value, $Kind)
    $key.Close()
}

function Disable-SvcOffline {
    param([string]$Svc)
    Set-RegVal 'zSYSTEM' "ControlSet001\Services\$Svc" 'Start' `
        ([Microsoft.Win32.RegistryValueKind]::DWord) 4
}

#endregion

#region ─── DEFENDER HALT PAYLOAD ─────────────────────────────────────────────
#
#  This is the complete DefenderHalt.ps1 source embedded as a here-string.
#  The builder will:
#    1. Write it to C:\GameMode\DefenderHalt.ps1 inside the mounted image
#    2. Inject a scheduled task XML that runs on first user logon
#    3. The task creates desktop shortcuts then deletes itself
#
$DefenderHaltSource = @'
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Defender Gaming Halt — suspend Defender for gaming, restore with one click.
.PARAMETER Mode
    Halt (default) or Restore
.PARAMETER Silent
    Suppress console output (used by desktop shortcuts)
#>
param(
    [ValidateSet('Halt','Restore')]
    [string]$Mode = 'Halt',
    [switch]$Silent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$StateFile  = "$env:ProgramData\DefenderHalt\state.json"
$LogFile    = "$env:ProgramData\DefenderHalt\halt.log"
$FilterName = 'WdFilter'
$Processes  = @('MsMpEng','MsSense','NisSrv','SgrmBroker')
$Services   = @('WinDefend','WdNisSvc','Sense')

[void][System.IO.Directory]::CreateDirectory("$env:ProgramData\DefenderHalt")

# ── P/Invoke: NtSuspendProcess / NtResumeProcess ──────────────────────────────
if (-not ('DefenderHalt.NativeMethods' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace DefenderHalt {
    public static class NativeMethods {
        [DllImport("ntdll.dll")]
        public static extern int NtSuspendProcess(IntPtr hProcess);
        [DllImport("ntdll.dll")]
        public static extern int NtResumeProcess(IntPtr hProcess);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CloseHandle(IntPtr h);
        public const uint PROCESS_SUSPEND_RESUME = 0x0800;
    }
}
"@
}

function Suspend-ProcessById {
    param([int]$Pid)
    $h = [DefenderHalt.NativeMethods]::OpenProcess(
        [DefenderHalt.NativeMethods]::PROCESS_SUSPEND_RESUME, $false, $Pid)
    if ($h -eq [IntPtr]::Zero) { return $false }
    $r = [DefenderHalt.NativeMethods]::NtSuspendProcess($h)
    [DefenderHalt.NativeMethods]::CloseHandle($h) | Out-Null
    return ($r -eq 0)
}

function Resume-ProcessById {
    param([int]$Pid)
    $h = [DefenderHalt.NativeMethods]::OpenProcess(
        [DefenderHalt.NativeMethods]::PROCESS_SUSPEND_RESUME, $false, $Pid)
    if ($h -eq [IntPtr]::Zero) { return $false }
    $r = [DefenderHalt.NativeMethods]::NtResumeProcess($h)
    [DefenderHalt.NativeMethods]::CloseHandle($h) | Out-Null
    return ($r -eq 0)
}

function Write-Log {
    param([string]$Msg)
    $line = "[$([datetime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))] $Msg"
    if (-not $Silent) { Write-Host $line }
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Show-Balloon {
    param([string]$Title, [string]$Body, [string]$Icon = 'Info')
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $n = New-Object System.Windows.Forms.NotifyIcon
        $n.Icon            = [System.Drawing.SystemIcons]::Shield
        $n.Visible         = $true
        $n.BalloonTipTitle = $Title
        $n.BalloonTipText  = $Body
        $n.BalloonTipIcon  = $Icon
        $n.ShowBalloonTip(4000)
        Start-Sleep -Seconds 5
        $n.Dispose()
    } catch {}
}

function Stop-ServiceFast {
    param([string]$Svc)
    & sc.exe stop $Svc 2>&1 | Out-Null
    $waited = 0
    while ($waited -lt 8000) {
        $s = (Get-Service -Name $Svc -ErrorAction SilentlyContinue).Status
        if ($s -in 'Stopped','') { break }
        Start-Sleep -Milliseconds 300; $waited += 300
    }
}

function Start-ServiceFast {
    param([string]$Svc)
    & sc.exe start $Svc 2>&1 | Out-Null
}

function Test-TamperProtection {
    return ((Get-MpPreference -ErrorAction SilentlyContinue).IsTamperProtected -eq $true)
}

# ── HALT ──────────────────────────────────────────────────────────────────────
function Invoke-Halt {
    Write-Log '── DEFENDER HALT START ──────────────────────'

    if (Test-TamperProtection) {
        Write-Log 'ERROR: Tamper Protection is ON.'
        Write-Host ''
        Write-Host ' Tamper Protection must be OFF before Game Mode will work.' -ForegroundColor Red
        Write-Host ' Windows Security -> Virus & threat protection'              -ForegroundColor Yellow
        Write-Host '   -> Manage settings -> Tamper Protection -> OFF'           -ForegroundColor Yellow
        Write-Host ' You only need to do this once.'                             -ForegroundColor Yellow
        exit 1
    }

    $state = @{ Timestamp = [datetime]::UtcNow.ToString('o'); Services = @{}; Pids = @(); RtpWasOn = $false }
    foreach ($svc in $Services) {
        $state.Services[$svc] = (Get-Service $svc -ErrorAction SilentlyContinue).StartType.ToString()
    }
    try { $state.RtpWasOn = (Get-MpPreference).DisableRealtimeMonitoring -eq $false } catch {}

    # 1. Disable real-time monitoring (reversible, no policy write)
    Write-Log 'Disabling real-time monitoring...'
    try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop }
    catch { Write-Log "  RTP disable warning: $_" }

    # 2. Stop services
    Write-Log 'Stopping Defender services...'
    foreach ($svc in $Services) {
        try { Stop-ServiceFast $svc; Write-Log "  Stopped $svc" }
        catch { Write-Log "  $svc already stopped" }
    }

    # 3. Unload WdFilter minifilter (biggest CPU/RAM contributor — intercepts all file I/O)
    Write-Log 'Unloading WdFilter minifilter...'
    try {
        $r = & fltMC unload $FilterName 2>&1
        Write-Log "  fltMC: $r"
    } catch { Write-Log "  WdFilter unload warning: $_" }

    # 4. Suspend surviving Defender processes at NT level (0 CPU, stays in RAM)
    Write-Log 'Suspending Defender processes...'
    $pids = [System.Collections.Generic.List[int]]::new()
    foreach ($name in $Processes) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
            if (Suspend-ProcessById $_.Id) {
                $pids.Add($_.Id)
                Write-Log "  Suspended $name (PID $($_.Id))"
            }
        }
    }
    $state.Pids = $pids.ToArray()

    $state | ConvertTo-Json -Depth 5 | Set-Content -Path $StateFile -Force
    Write-Log '── DEFENDER HALTED — CPU/RAM freed ──────────'

    Show-Balloon -Title 'Game Mode ON' `
        -Body 'Defender suspended. Double-click "Game Mode OFF" when done gaming.' `
        -Icon 'Warning'
}

# ── RESTORE ───────────────────────────────────────────────────────────────────
function Invoke-Restore {
    Write-Log '── DEFENDER RESTORE START ───────────────────'

    $state = if (Test-Path $StateFile) { Get-Content $StateFile | ConvertFrom-Json } else { $null }

    # 1. Resume suspended processes
    Write-Log 'Resuming processes...'
    if ($state -and $state.Pids) {
        foreach ($pid in $state.Pids) {
            try { Resume-ProcessById $pid | Out-Null; Write-Log "  Resumed PID $pid" }
            catch { Write-Log "  PID $pid already gone" }
        }
    } else {
        foreach ($name in $Processes) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
                Resume-ProcessById $_.Id | Out-Null
            }
        }
    }

    # 2. Reload WdFilter before starting services
    Write-Log 'Reloading WdFilter...'
    try { $r = & fltMC load $FilterName 2>&1; Write-Log "  fltMC: $r" }
    catch { Write-Log "  WdFilter load warning: $_" }

    # 3. Restart services (reverse dependency order)
    Write-Log 'Restarting services...'
    [array]::Reverse($Services)
    foreach ($svc in $Services) {
        try { Start-ServiceFast $svc; Write-Log "  Started $svc" }
        catch { Write-Log "  Could not start $svc: $_" }
        Start-Sleep -Milliseconds 400
    }
    [array]::Reverse($Services)   # restore original order

    # 4. Re-enable real-time protection
    Write-Log 'Re-enabling real-time monitoring...'
    $tries = 0
    do {
        try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; break }
        catch { $tries++; Start-Sleep -Milliseconds 800 }
    } while ($tries -lt 10)

    # 5. Sync signatures
    try { Update-MpSignature -ErrorAction SilentlyContinue }
    catch { Write-Log '  Signature sync queued' }

    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Log '── DEFENDER RESTORED ────────────────────────'

    Show-Balloon -Title 'Game Mode OFF' -Body 'Defender fully restored.' -Icon 'Info'
}

switch ($Mode) {
    'Halt'    { Invoke-Halt    }
    'Restore' { Invoke-Restore }
}
'@

#endregion

#region ─── FIRST-LOGON TASK XML ──────────────────────────────────────────────

$FirstLogonTaskXml = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Creates Game Mode desktop shortcuts on first login. Self-deletes after running.</Description>
    <URI>\GameModeSetup</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-32-545</GroupId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command "
$scriptPath = 'C:\GameMode\DefenderHalt.ps1';
$pubDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory');

function New-GameShortcut {
    param([string]$Name, [string]$Args, [string]$Desc, [int]$IconIdx)
    $lnkPath = Join-Path $pubDesktop ($Name + '.lnk');
    $wsh = New-Object -ComObject WScript.Shell;
    $sc  = $wsh.CreateShortcut($lnkPath);
    $sc.TargetPath       = 'powershell.exe';
    $sc.Arguments        = $Args;
    $sc.WorkingDirectory = 'C:\GameMode';
    $sc.Description      = $Desc;
    $sc.IconLocation     = 'shell32.dll,' + $IconIdx;
    $sc.WindowStyle      = 7;
    $sc.Save();
    # Set RunAs flag in the shortcut binary (byte offset 0x15, bit 0x20)
    $bytes = [System.IO.File]::ReadAllBytes($lnkPath);
    $bytes[0x15] = $bytes[0x15] -bor 0x20;
    [System.IO.File]::WriteAllBytes($lnkPath, $bytes);
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($sc)  | Out-Null;
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($wsh) | Out-Null;
}

New-GameShortcut `
    -Name    'Game Mode ON' `
    -Args    ('-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File \"' + $scriptPath + '\" -Mode Halt -Silent') `
    -Desc    'Suspend Defender for gaming (restore with Game Mode OFF)' `
    -IconIdx 47;

New-GameShortcut `
    -Name    'Game Mode OFF' `
    -Args    ('-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File \"' + $scriptPath + '\" -Mode Restore -Silent') `
    -Desc    'Restore Defender after gaming' `
    -IconIdx 44;

Unregister-ScheduledTask -TaskName 'GameModeSetup' -Confirm:`$false -ErrorAction SilentlyContinue;
"
      </Arguments>
    </Exec>
  </Actions>
</Task>
'@

#endregion

#region ─── PRE-FLIGHT ────────────────────────────────────────────────────────

Write-Step 'Pre-flight checks...'
if (-not (Test-Path $Oscdimg)) {
    throw "oscdimg.exe not found.`n  Expected: $Oscdimg`n  Install Windows ADK Deployment Tools."
}

Get-WindowsImage -Mounted | ForEach-Object {
    Dismount-WindowsImage -Path $_.Path -Discard -ErrorAction SilentlyContinue
}

#endregion

#region ─── ISO INPUT & WIM ───────────────────────────────────────────────────
#
#  FIX: $ISO parameter has [ValidatePattern] which re-fires on every assignment.
#  We immediately copy to $ISODrive (plain string, no validator) and never
#  reassign $ISO again. All downstream path references use $ISODrive.
#

if (-not $ISO) { $ISO = Read-Host 'Enter mounted ISO drive letter (e.g. D)' }
$ISODrive = $ISO.TrimEnd(':').ToUpper() + ':'   # e.g. "D:"
$WimPath  = "$TempDir\install.wim"

if (Test-Path "$ISODrive\sources\install.wim") {
    Write-Step 'Copying install.wim -> scratch...'
    robocopy "$ISODrive\sources" $TempDir install.wim /J /R:0 /W:0 /NP /NDL /NFL | Out-Null
}
elseif (Test-Path "$ISODrive\sources\install.esd") {
    Write-Step 'Converting ESD -> WIM (no compression)...'
    Get-WindowsImage -ImagePath "$ISODrive\sources\install.esd"
    $Index = Read-Host 'Enter index to export'
    Export-WindowsImage `
        -SourceImagePath      "$ISODrive\sources\install.esd" `
        -SourceIndex          $Index `
        -DestinationImagePath $WimPath `
        -CompressionType      None
}
else { throw "No install.wim or install.esd found on $ISODrive" }

Write-Step 'Available editions:'
Get-WindowsImage -ImagePath $WimPath
$Index = Read-Host 'Enter desired edition index'

#endregion

#region ─── COPY ISO STRUCTURE ────────────────────────────────────────────────

Write-Step 'Copying ISO structure...'
robocopy "$ISODrive" $BuildRoot /E /J /MT:16 /R:0 /W:0 /XF install.wim install.esd /NFL /NDL /NP | Out-Null
Move-Item $WimPath "$BuildRoot\sources\install.wim" -Force

# Strip read-only attributes inherited from the ISO (optical media marks everything R/O).
# Without this, DISM refuses to mount for read-write and boot.wim patching also fails.
Write-Step 'Clearing read-only attributes on build tree...'
Get-ChildItem -Path $BuildRoot -Recurse -Force |
    Where-Object { -not $_.PSIsContainer -and ($_.Attributes -band [IO.FileAttributes]::ReadOnly) } |
    ForEach-Object { $_.Attributes = $_.Attributes -band -bnot [IO.FileAttributes]::ReadOnly }
Write-Ok 'Read-only attributes cleared'

#endregion

#region ─── MOUNT install.wim ────────────────────────────────────────────────

Write-Step "Mounting install.wim (index $Index)..."
Mount-WindowsImage `
    -ImagePath        "$BuildRoot\sources\install.wim" `
    -Index            $Index `
    -Path             $MountDir `
    -ScratchDirectory $TempDir

# Only take ownership of the config directory where hive files live.
# Taking ownership of the entire mount tree corrupts DISM's mount state
# and breaks WinSxS protected files — target only what reg.exe needs.
Write-Step 'Taking ownership of config hives (required for reg load)...'
$configDir  = "$MountDir\Windows\System32\config"
$ntuserFile = "$MountDir\Users\Default\NTUSER.DAT"
& takeown '/F' $configDir  '/R' '/D' 'Y' | Out-Null
& icacls  $configDir  '/grant' "Administrators:(F)" '/T' '/C' | Out-Null
& takeown '/F' $ntuserFile | Out-Null
& icacls  $ntuserFile '/grant' "Administrators:(F)"  | Out-Null
Write-Ok 'Ownership granted'

#endregion

#region ─── INJECT DEFENDER HALT + SHORTCUTS ─────────────────────────────────

Write-Step 'Injecting DefenderHalt.ps1 into image...'

# 1. Write the script into the image at a clean, permanent location
$GameModeDir = "$MountDir\GameMode"
[void][System.IO.Directory]::CreateDirectory($GameModeDir)
[System.IO.File]::WriteAllText("$GameModeDir\DefenderHalt.ps1", $DefenderHaltSource,
    [System.Text.Encoding]::UTF8)
Write-Ok 'C:\GameMode\DefenderHalt.ps1 written'

# 2. Write the scheduled task XML into the image's task store
$TaskDir = "$MountDir\Windows\System32\Tasks"
[void][System.IO.Directory]::CreateDirectory($TaskDir)
[System.IO.File]::WriteAllText("$TaskDir\GameModeSetup", $FirstLogonTaskXml,
    [System.Text.Encoding]::Unicode)   # Task XML MUST be UTF-16 for Windows to parse it
Write-Ok 'Scheduled task GameModeSetup injected'

# 3. Register the task in the offline SOFTWARE hive
Write-Step 'Registering task in offline SOFTWARE hive...'
Open-OfflineHive "$MountDir\Windows\System32\config\SOFTWARE" 'zSOFTWARE'

$DW = [Microsoft.Win32.RegistryValueKind]::DWord
$SW = [Microsoft.Win32.RegistryValueKind]::String

$taskTreeSub = 'Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\GameModeSetup'
Set-RegVal 'zSOFTWARE' $taskTreeSub 'Index' $DW 0
Set-RegVal 'zSOFTWARE' $taskTreeSub 'SD'    ([Microsoft.Win32.RegistryValueKind]::Binary) `
    ([byte[]](0x01,0x00,0x04,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x14,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

Close-OfflineHive 'zSOFTWARE'
Write-Ok 'TaskCache entry written'

#endregion

#region ─── REMOVE PROVISIONED APPS ──────────────────────────────────────────

Write-Step 'Removing provisioned apps...'

$AppPrefixes = [System.Collections.Generic.HashSet[string]]@(
    'Clipchamp','Copilot','Xbox','XboxApp','XboxGameOverlay',
    'XboxIdentityProvider','XboxSpeechToTextOverlay','XboxTcuiSdk',
    'Teams','TikTok','Spotify','DevHome',
    'People','Wallet','Maps','BingMaps',
    'FeedbackHub','GetHelp','GetStarted',
    'Solitaire','BingSolitaire',
    'Bing','BingWeather','BingNews','BingFinance','BingSports',
    'MixedReality','Skype','Alarms','SoundRecorder',
    'Todos','PowerAutomate','YourPhone','PhoneLink',
    'OfficeHub','OneNote','StickyNotes',
    'ZuneMusic','ZuneVideo','Paint3D','3DViewer',
    'OutlookForWindows','WindowsFeedbackHub'
)

$ToRemove = Get-AppxProvisionedPackage -Path $MountDir | Where-Object {
    $dn = $_.DisplayName
    $AppPrefixes | Where-Object { $dn -like "*$_*" } | Select-Object -First 1
}

foreach ($Pkg in $ToRemove) {
    try {
        Remove-AppxProvisionedPackage -Path $MountDir -PackageName $Pkg.PackageName | Out-Null
        Write-Ok $Pkg.DisplayName
    } catch { Write-Warn "Skip $($Pkg.DisplayName): $_" }
}

#endregion

#region ─── REMOVE OPTIONAL FEATURES ─────────────────────────────────────────

Write-Step 'Removing optional features...'

$FeatureNames = (Get-WindowsOptionalFeature -Path $MountDir).Where({ $_.State -eq 'Enabled' }).FeatureName

@(
    'Internet-Explorer-Optional-amd64','MathRecognizer','WorkFolders-Client',
    'Hello-Face','TelnetClient','TFTP','Printing-XPSServices-Features',
    'MSRDC-Infrastructure','MicrosoftWindowsPowerShellV2','Recall',
    'WCF-Services45','WCF-TCP-PortSharing45'
) | ForEach-Object {
    if ($FeatureNames -contains $_) {
        try {
            Disable-WindowsOptionalFeature -Path $MountDir -FeatureName $_ -Remove -NoRestart | Out-Null
            Write-Ok $_
        } catch { Write-Warn "Could not remove $_" }
    } else { Write-Skip $_ }
}

#endregion

#region ─── OFFLINE REGISTRY TWEAKS ──────────────────────────────────────────

Write-Step 'Loading offline registry hives...'
Open-OfflineHive "$MountDir\Windows\System32\config\SOFTWARE" 'zSOFTWARE'
Open-OfflineHive "$MountDir\Windows\System32\config\SYSTEM"   'zSYSTEM'
Open-OfflineHive "$MountDir\Windows\System32\config\DEFAULT"  'zDEFAULT'
Open-OfflineHive "$MountDir\Users\Default\NTUSER.DAT"          'zNTUSER'

$DW  = [Microsoft.Win32.RegistryValueKind]::DWord
$STR = [Microsoft.Win32.RegistryValueKind]::String

Write-Step 'Hardware bypasses...'
foreach ($n in 'BypassCPUCheck','BypassRAMCheck','BypassSecureBootCheck','BypassStorageCheck','BypassTPMCheck') {
    Set-RegVal 'zSYSTEM' 'Setup\LabConfig' $n $DW 1
}

Write-Step 'Disabling services...'
@(
    'DiagTrack','WerSvc','DPS','PcaSvc',
    'XblAuthManager','XblGameSave','XboxNetApiSvc',
    'SysMain','WSearch','MapsBroker','RetailDemo','RemoteRegistry',
    'lfsvc','Fax','icssvc','SharedAccess',
    'TermService','SessionEnv','UmRdpService',
    'WbioSrvc','WMPNetworkSvc'
) | ForEach-Object {
    try { Disable-SvcOffline $_; Write-Ok $_ }
    catch { Write-Warn "Svc not found: $_" }
}

Write-Step 'Telemetry and privacy...'
Set-RegVal 'zSOFTWARE' 'Policies\Microsoft\Windows\DataCollection'       'AllowTelemetry'                 $DW 0
Set-RegVal 'zSOFTWARE' 'Policies\Microsoft\Windows\DataCollection'       'DisableOneSettingsDownloads'    $DW 1
Set-RegVal 'zSOFTWARE' 'Policies\Microsoft\Windows\CloudContent'         'DisableWindowsConsumerFeatures' $DW 1
Set-RegVal 'zSOFTWARE' 'Policies\Microsoft\PushToInstall'                'DisablePushToInstall'           $DW 1
Set-RegVal 'zSOFTWARE' 'Policies\Microsoft\Windows\WindowsCopilot'       'TurnOffWindowsCopilot'          $DW 1
Set-RegVal 'zSOFTWARE' 'Policies\Microsoft\Windows\AppPrivacy'           'LetAppsRunInBackground'         $DW 2
Set-RegVal 'zSOFTWARE' 'Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode'                 $DW 0
Set-RegVal 'zSOFTWARE' 'Policies\Microsoft\Windows\GameDVR'              'AllowGameDVR'                   $DW 0
Set-RegVal 'zSOFTWARE' 'Policies\Microsoft\Windows\Windows Search'       'AllowCortana'                   $DW 0
Set-RegVal 'zSOFTWARE' 'Microsoft\Windows\CurrentVersion\OOBE'           'BypassNRO'                      $DW 1

Write-Step 'Memory management...'
$mm = 'ControlSet001\Control\Session Manager\Memory Management'
Set-RegVal 'zSYSTEM' "$mm\PrefetchParameters" 'EnablePrefetcher'       $DW 0
Set-RegVal 'zSYSTEM' "$mm\PrefetchParameters" 'EnableSuperfetch'       $DW 0
Set-RegVal 'zSYSTEM' $mm                      'DisablePagingExecutive' $DW 1
Set-RegVal 'zSYSTEM' $mm                      'LargeSystemCache'       $DW 0
Set-RegVal 'zSYSTEM' 'ControlSet001\Control\Session Manager' 'SvcHostSplitThresholdInKB' $DW 4194304

Set-RegVal 'zSYSTEM' 'ControlSet001\Control\Session Manager\Power'  'HiberbootEnabled'                  $DW 0
Set-RegVal 'zSYSTEM' 'ControlSet001\Control\DeviceGuard'            'EnableVirtualizationBasedSecurity' $DW 0
Set-RegVal 'zSYSTEM' 'ControlSet001\Control\DeviceGuard'            'RequirePlatformSecurityFeatures'   $DW 0

Set-RegVal 'zNTUSER' 'Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' 'VisualFXSetting' $DW 2
Set-RegVal 'zNTUSER' 'Control Panel\Desktop\WindowMetrics'                              'MinAnimate'       $STR '0'

Write-Step 'Unloading hives...'
Close-OfflineHive 'zSOFTWARE'
Close-OfflineHive 'zSYSTEM'
Close-OfflineHive 'zDEFAULT'
Close-OfflineHive 'zNTUSER'

#endregion

#region ─── TELEMETRY TASKS (parallel) ───────────────────────────────────────

Write-Step 'Removing telemetry tasks...'

$TasksRoot = "$MountDir\Windows\System32\Tasks\Microsoft\Windows"
$pool = [RunspaceFactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
$pool.Open()
$jobs = @(
    'Application Experience','Customer Experience Improvement Program',
    'Feedback','Maps','Power Efficiency Diagnostics','DiskDiagnostic',
    'MUI','Multimedia','Sysmain','PushToInstall','CloudExperienceHost',
    'License Manager','WCM','Autochk','Diagnosis'
) | ForEach-Object {
    $p2 = Join-Path $TasksRoot $_
    $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
    [void]$ps.AddScript({ param($p)
        if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue; "OK  $p" }
        else { "SKIP $p" }
    }).AddArgument($p2)
    @{ PS = $ps; AR = $ps.BeginInvoke() }
}
$jobs | ForEach-Object {
    $_.PS.EndInvoke($_.AR) | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    $_.PS.Dispose()
}
$pool.Close(); $pool.Dispose()

#endregion

#region ─── MISC CLEANUP ──────────────────────────────────────────────────────

Remove-Item "$MountDir\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" `
    -ErrorAction SilentlyContinue

#endregion

#region ─── COMMIT install.wim ───────────────────────────────────────────────

Write-Step 'Committing install.wim...'
Dismount-WindowsImage -Path $MountDir -Save

#endregion

#region ─── PATCH boot.wim ───────────────────────────────────────────────────

Write-Step 'Patching boot.wim...'
$bootWimPath = "$BuildRoot\sources\boot.wim"
Set-ItemProperty -Path $bootWimPath -Name Attributes -Value ([IO.FileAttributes]::Normal)
Mount-WindowsImage `
    -ImagePath        $bootWimPath `
    -Index            2 `
    -Path             $MountDir `
    -ScratchDirectory $TempDir

# Only take ownership of config dir in boot.wim mount
$configDir = "$MountDir\Windows\System32\config"
& takeown '/F' $configDir '/R' '/D' 'Y' | Out-Null
& icacls  $configDir '/grant' "Administrators:(F)" '/T' '/C' | Out-Null

Open-OfflineHive "$MountDir\Windows\System32\config\SYSTEM" 'zSYSTEM'
foreach ($n in 'BypassCPUCheck','BypassRAMCheck','BypassSecureBootCheck','BypassStorageCheck','BypassTPMCheck') {
    Set-RegVal 'zSYSTEM' 'Setup\LabConfig' $n $DW 1
}
Close-OfflineHive 'zSYSTEM'

Dismount-WindowsImage -Path $MountDir -Save

#endregion

#region ─── BUILD ISO ─────────────────────────────────────────────────────────

Write-Step 'Building ISO...'
& $Oscdimg `
    -m -u2 -udfver102 -yo `
    "-bootdata:2#p0,e,b$BuildRoot\boot\etfsboot.com#pEF,e,b$BuildRoot\efi\microsoft\boot\efisys.bin" `
    $BuildRoot `
    $OutputISO

#endregion

#region ─── CLEANUP ───────────────────────────────────────────────────────────

Write-Step 'Cleaning up (background)...'
$null = Start-Job -ScriptBlock {
    param($m, $t)
    Remove-Item $m -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $t -Recurse -Force -ErrorAction SilentlyContinue
} -ArgumentList $MountDir, $TempDir

#endregion

Write-Host ''
Write-Host '=======================================================' -ForegroundColor Green
Write-Host '  BUILD COMPLETE'                                         -ForegroundColor Green
Write-Host "  ISO  : $OutputISO"                                      -ForegroundColor Green
Write-Host '  After install, log in once — shortcuts appear on Desktop automatically.' -ForegroundColor Cyan
Write-Host '  First: disable Tamper Protection in Windows Security.'  -ForegroundColor Yellow
Write-Host '  Then:  double-click "Game Mode ON" before gaming.'      -ForegroundColor Yellow
Write-Host '=======================================================' -ForegroundColor Green
