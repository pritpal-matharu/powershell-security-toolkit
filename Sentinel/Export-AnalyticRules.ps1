<#
.SYNOPSIS
Exports Microsoft Sentinel analytic rules to JSON files for backup or migration.

.DESCRIPTION
This script connects to a Microsoft Sentinel workspace and exports all analytic rules
to JSON format. Useful for version control, backup, and migration scenarios.

.PARAMETER WorkspaceName
The name of the Microsoft Sentinel workspace.

.PARAMETER ResourceGroup
The resource group containing the Sentinel workspace.

.PARAMETER ExportDir
Directory where exported JSON files will be saved. Default is current directory.

.EXAMPLE
Export-AnalyticRules -WorkspaceName 'MySentinelWorkspace' -ResourceGroup 'MyResourceGroup' -ExportDir 'C:\Exports'

#>

param(
    [Parameter(Mandatory=$true)]
    [string]$WorkspaceName,
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportDir = '.'
)

# Requires: Install-Module Az.SecurityInsights -Force

try {
    Write-Host "[*] Starting export of Sentinel analytic rules" -ForegroundColor Yellow
    Write-Host "[*] Workspace: $WorkspaceName" -ForegroundColor Cyan
    Write-Host "[*] Resource Group: $ResourceGroup" -ForegroundColor Cyan
    
    # Create export directory if it doesn't exist
    if (-not (Test-Path $ExportDir)) {
        New-Item -Path $ExportDir -ItemType Directory -Force | Out-Null
        Write-Host "[+] Created export directory: $ExportDir" -ForegroundColor Green
    }
    
    # Get all alert rules from Sentinel workspace
    Write-Host "[*] Retrieving analytic rules from workspace..." -ForegroundColor Cyan
    
    $rules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName -ErrorAction Stop
    
    if ($rules) {
        Write-Host "[+] Found $($rules.Count) analytic rules" -ForegroundColor Green
        
        $ruleCount = 0
        
        foreach ($rule in $rules) {
            try {
                # Clean filename
                $fileName = $rule.DisplayName -replace '[^a-zA-Z0-9_-]', '_'
                $filePath = Join-Path $ExportDir "$fileName.json"
                
                # Export rule to JSON
                $rule | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Force -Encoding UTF8
                
                Write-Host "[+] Exported: $($rule.DisplayName)" -ForegroundColor Green
                $ruleCount++
            }
            catch {
                Write-Warning "Failed to export rule '$($rule.DisplayName)': $_"
            }
        }
        
        # Output device isolation status
        Write-Host "`n[*] Export Summary" -ForegroundColor Cyan
        Write-Host "Total Rules: $($rules.Count)"
        Write-Host "Successfully Exported: $ruleCount"
        Write-Host "Export Location: $exportDir"
        Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    }
    else {
        Write-Host "[-] No analytic rules found in workspace" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Failed to export analytic rules: $_"
    exit 1
}
