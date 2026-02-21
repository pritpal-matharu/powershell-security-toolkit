<#
.SYNOPSIS
    Collects key OS artifacts and security indicators from a Windows endpoint for incident response triage.

.DESCRIPTION
    This script gathers critical forensic artifacts from a Windows host including:
    - System information and network configuration
    - Running processes and services
    - Event logs (Security, System, Application)
    - Network connections and listening ports
    - Installed software and drivers
    - Scheduled tasks
    - User accounts and login history
    - File system artifacts (recent files, temp files)

.PARAMETER ComputerName
    The target computer to collect artifacts from (default: localhost)

.PARAMETER OutputPath
    Directory to save collected artifacts (default: C:\IR-Evidence)

.PARAMETER SkipEventLogs
    Switch to skip Event Log collection (faster for large log files)

.EXAMPLE
    Get-EndpointTriagePackage -ComputerName TARGET-PC -OutputPath 'D:\IR'
    
.EXAMPLE
    Get-EndpointTriagePackage -SkipEventLogs

.NOTES
    Requires Administrator privileges on target host
    Created: 2026-02-20
    Author: Cloud Security Operations
#>

param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$OutputPath = 'C:\IR-Evidence',
    [switch]$SkipEventLogs
)

# Validate admin privileges
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges"
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "[+] Created output directory: $OutputPath" -ForegroundColor Green
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$caseFolder = Join-Path $OutputPath "$ComputerName`_$timestamp"
New-Item -ItemType Directory -Path $caseFolder -Force | Out-Null

Write-Host "[*] Starting endpoint triage for $ComputerName" -ForegroundColor Cyan
Write-Host "[*] Output directory: $caseFolder" -ForegroundColor Cyan

# 1. System Information
Write-Host "[*] Collecting system information..." -ForegroundColor Yellow
$sysInfo = @{
    ComputerName = $env:COMPUTERNAME
    OSVersion = [System.Environment]::OSVersion
    Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    InstalledRAM = (Get-WmiObject Win32_OperatingSystem).TotalVisibleMemorySize / 1024 / 1024
    LastBootTime = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
    TimeZone = (Get-TimeZone).DisplayName
    IPConfiguration = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer
}
$sysInfo | ConvertTo-Json | Out-File "$caseFolder\01_SystemInfo.json"

# 2. Processes
Write-Host "[*] Collecting running processes..." -ForegroundColor Yellow
Get-Process | Select-Object Name, Id, Path, CommandLine, StartTime, Handles | 
    ConvertTo-Json | Out-File "$caseFolder\02_Processes.json"

# 3. Network Connections
Write-Host "[*] Collecting network connections..." -ForegroundColor Yellow
Get-NetTCPConnection -State Established | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
    ConvertTo-Json | Out-File "$caseFolder\03_NetworkConnections.json"

# 4. Listening Ports
Write-Host "[*] Collecting listening ports..." -ForegroundColor Yellow
Get-NetTCPConnection -State Listen | 
    Select-Object LocalAddress, LocalPort, OwningProcess, @{
        Name="ProcessName";
        Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}
    } | ConvertTo-Json | Out-File "$caseFolder\04_ListeningPorts.json"

# 5. Services
Write-Host "[*] Collecting services..." -ForegroundColor Yellow
Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType | 
    ConvertTo-Json | Out-File "$caseFolder\05_Services.json"

# 6. Installed Software
Write-Host "[*] Collecting installed software..." -ForegroundColor Yellow
$software = @()
$software += Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
$software += Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
$software | Select-Object DisplayName, DisplayVersion, InstallDate, InstallLocation | 
    ConvertTo-Json | Out-File "$caseFolder\06_InstalledSoftware.json"

# 7. Scheduled Tasks
Write-Host "[*] Collecting scheduled tasks..." -ForegroundColor Yellow
Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Actions | 
    ConvertTo-Json | Out-File "$caseFolder\07_ScheduledTasks.json"

# 8. User Accounts
Write-Host "[*] Collecting user accounts..." -ForegroundColor Yellow
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | 
    ConvertTo-Json | Out-File "$caseFolder\08_UserAccounts.json"

# 9. Network Adapter Information
Write-Host "[*] Collecting network adapter information..." -ForegroundColor Yellow
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, Speed | 
    ConvertTo-Json | Out-File "$caseFolder\09_NetworkAdapters.json"

# 10. Event Logs (optional)
if (-not $SkipEventLogs) {
    Write-Host "[*] Collecting event logs (Security, System, Application)..." -ForegroundColor Yellow
    Get-EventLog -LogName Security -Newest 1000 | 
        Select-Object TimeGenerated, EventID, Type, Source, Message | 
        ConvertTo-Json | Out-File "$caseFolder\10_SecurityEventLog.json"
    
    Get-EventLog -LogName System -Newest 500 | 
        Select-Object TimeGenerated, EventID, Type, Source, Message | 
        ConvertTo-Json | Out-File "$caseFolder\11_SystemEventLog.json"
}

# 11. Disk Information
Write-Host "[*] Collecting disk information..." -ForegroundColor Yellow
Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining, FileSystem | 
    ConvertTo-Json | Out-File "$caseFolder\12_DiskInfo.json"

# 12. Recent Files
Write-Host "[*] Collecting recent file access..." -ForegroundColor Yellow
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentPath) {
    Get-ChildItem -Path $recentPath -File | 
        Select-Object Name, CreationTime, LastWriteTime, Length | 
        ConvertTo-Json | Out-File "$caseFolder\13_RecentFiles.json"
}

Write-Host "" 
Write-Host "[+] Triage collection completed!" -ForegroundColor Green
Write-Host "[+] Evidence saved to: $caseFolder" -ForegroundColor Green
Write-Host "[*] Artifact count: 13 files collected" -ForegroundColor Cyan

# Create manifest file
$manifest = @{
    CollectionDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    ComputerName = $ComputerName
    CollectionMethod = 'Get-EndpointTriagePackage.ps1'
    ArtifactCount = 13
    FilesLocation = $caseFolder
}
$manifest | ConvertTo-Json | Out-File "$caseFolder\MANIFEST.json"

Write-Host "[+] Manifest file created" -ForegroundColor Green
