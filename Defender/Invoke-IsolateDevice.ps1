<#
.SYNOPSIS
Isolates a device in Microsoft Defender for Endpoint by restricting network communication.

.DESCRIPTION
This script initiates device isolation in Microsoft Defender for Endpoint. The isolated device
can only communicate with specified IPs, preventing lateral movement and data exfiltration.

.PARAMETER DeviceId
The unique device ID in Microsoft Defender for Endpoint (machine ID).

.PARAMETER IsolationType
The type of isolation: 'Full' or 'Selective'. Default is 'Selective'.

.PARAMETER Comment
Optional comment describing the reason for isolation.

.EXAMPLE
Invoke-IsolateDevice -DeviceId "e8b41cc6ae906f4b87e2b5aebbb4f6" -IsolationType "Full" -Comment "Suspected compromise"

#>

param(
    [Parameter(Mandatory=$true)]
    [string]$DeviceId,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Full', 'Selective')]
    [string]$IsolationType = 'Selective',
    
    [Parameter(Mandatory=$false)]
    [string]$Comment
)

# Requires Microsoft Graph API authentication
# Install-Module Microsoft.Graph -Force -Scope CurrentUser

try {
    Write-Host "[*] Initiating device isolation for device: $DeviceId" -ForegroundColor Yellow
    
    # Get device details first
    $deviceUri = "https://api.securitycenter.windows.com/api/machines/$DeviceId"
    
    Write-Host "[*] Fetching device details..." -ForegroundColor Cyan
    
    # Prepare isolation request
    $isolationBody = @{
        IsolationType = $IsolationType
        Comment = $Comment
    } | ConvertTo-Json
    
    # Send isolation request to Microsoft Defender API
    $isolateUri = "https://api.securitycenter.windows.com/api/machines/$DeviceId/isolateMachine"
    
    $isolationResponse = Invoke-RestMethod -Method Post -Uri $isolateUri -ContentType "application/json" -Body $isolationBody -ErrorAction Stop
    
    if ($isolationResponse.id) {
        Write-Host "[+] Device isolation initiated successfully!" -ForegroundColor Green
        Write-Host "[+] Request ID: $($isolationResponse.id)" -ForegroundColor Green
        Write-Host "[+] Status: $($isolationResponse.status)" -ForegroundColor Green
        Write-Host "[+] Isolation Type: $($isolationResponse.isolationType)" -ForegroundColor Green
    }
    else {
        Write-Warning "Isolation request may not have completed as expected. Response: $isolationResponse"
    }
    
    # Output device isolation status
    Write-Host "`n[*] Device Isolation Status" -ForegroundColor Cyan
    Write-Host "Device ID: $DeviceId"
    Write-Host "Isolation Type: $IsolationType"
    Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    
    if ($Comment) {
        Write-Host "Comment: $Comment"
    }
}
catch {
    Write-Error "Failed to isolate device: $_"
    exit 1
}
