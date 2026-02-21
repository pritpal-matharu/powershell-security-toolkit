<#
.SYNOPSIS
Retrieves suspicious sign-in activities from Azure AD/Entra ID using Microsoft Graph API.

.DESCRIPTION
This script queries Azure AD sign-in logs via Microsoft Graph to identify suspicious activities
including failed authentications, anomalous locations, and risky sign-in patterns.

.PARAMETER DaysBack
Number of days to look back for sign-in events. Default is 7 days.

.PARAMETER RiskLevel
Filter by risk level: 'high', 'medium', 'low', or 'none'. Default is 'high'.

.PARAMETER OutputPath
Path to export results to CSV file.

.EXAMPLE
Get-SuspiciousSignins -DaysBack 14 -RiskLevel 'high' -OutputPath 'C:\Reports\suspicious_signins.csv'

#>

param(
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 7,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('high', 'medium', 'low', 'none')]
    [string]$RiskLevel = 'high',
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)

# Requires: Install-Module Microsoft.Graph.Identity.SignIns -Force

try {
    Write-Host "[*] Retrieving suspicious sign-in activities from Azure AD" -ForegroundColor Yellow
    
    # Calculate date range
    $endDate = Get-Date
    $startDate = $endDate.AddDays(-$DaysBack)
    
    Write-Host "[*] Time range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan
    
    # Build KQL-style filter
    $filter = "createdDateTime ge {0} and createdDateTime le {1}" -f $startDate.ToString('O'), $endDate.ToString('O')
    
    if ($RiskLevel -ne 'none') {
        $filter += " and riskLevelDuringSignIn eq '$RiskLevel'"
    }
    
    Write-Host "[*] Applying filter: $filter" -ForegroundColor Cyan
    
    # Query sign-in logs via Graph API
    $signInLogs = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop
    
    if ($signInLogs) {
        Write-Host "[+] Found $($signInLogs.Count) suspicious sign-in events" -ForegroundColor Green
        
        # Process and display results
        $results = $signInLogs | Select-Object -Property @(
            'CreatedDateTime',
            'UserPrincipalName',
            'AppDisplayName',
            'ClientAppUsed',
            'RiskLevelDuringSignIn',
            'ConditionAccessStatus',
            'MfaDetail',
            'ResourceDisplayName',
            'Status',
            'IPAddress',
            'DeviceDetail'
        )
        
        # Display summary
        Write-Host "`n[*] Suspicious Sign-in Summary" -ForegroundColor Cyan
        Write-Host "Total Events: $($signInLogs.Count)"
        Write-Host "Date Range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))"
        Write-Host "Risk Level: $RiskLevel`n"
        
        # Export if path specified
        if ($OutputPath) {
            $results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            Write-Host "[+] Results exported to: $OutputPath" -ForegroundColor Green
        }
        else {
            # Display top 10 results
            $results | Select-Object -First 10 | Format-Table -AutoSize
        }
    }
    else {
        Write-Host "[-] No suspicious sign-in events found for the specified criteria" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Failed to retrieve sign-in logs: $_"
    exit 1
}
