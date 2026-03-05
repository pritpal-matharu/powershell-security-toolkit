<#
.SYNOPSIS
    Resolve-IPs-Parallel-v3.ps1 - Bulk IP-to-hostname resolver, compatible with PS 5.1 and PS 7+.

.NOTES
    v3 FIX: Removed -TimeoutMilliseconds from Test-Connection and -TimeOutSec from Resolve-DnsName.
    Both parameters are unavailable when PS7 loads the Windows PowerShell 5.1 DnsClient module
    (the common case on Windows). All timeout/retry logic now uses try/catch with -ErrorAction only.

.PARAMETER IPAddress
    One or more IP addresses to resolve. Accepts pipeline input.

.PARAMETER InputPath
    Path to a plain-text file containing one IP address per line.

.PARAMETER DnsServer
    Optional DNS server to use for all queries.

.PARAMETER TimeoutMs
    Retained for interface compatibility. Not passed to cmdlets (see v3 notes above).

.PARAMETER PingCount
    Number of ICMP echo requests to send (default: 1).

.PARAMETER PingTimeoutMs
    Retained for interface compatibility. Not passed to cmdlets (see v3 notes above).

.PARAMETER Parallel
    Use ForEach-Object -Parallel on PowerShell 7+. Ignored with a warning on PS 5.1.

.PARAMETER ThrottleLimit
    Maximum number of parallel threads (default: 100). Only used when -Parallel is active.

.PARAMETER OutputCsv
    If specified, export results to this CSV file path (UTF-8, no type info).

.PARAMETER OnlyResolved
    Only emit rows where PTR lookup succeeded.

.PARAMETER IncludeUnreachable
    Include IPs that fail the ping test.

.PARAMETER ValidateForward
    After PTR success, resolve forward A/AAAA records and check if the original IP appears.

.PARAMETER CaptureBothFamilies
    When -ValidateForward is set, always capture both A and AAAA records regardless of IP version.

.PARAMETER Colorize
    Print a colorized fixed-width table to the console using Write-Host. Objects are not emitted.

.EXAMPLE
    .\Resolve-IPs-Parallel-v3.ps1 -InputPath .\ips.txt -DnsServer 10.0.3.58 -ValidateForward -Colorize

.EXAMPLE
    pwsh.exe -File .\Resolve-IPs-Parallel-v3.ps1 -InputPath .\ips.txt -DnsServer 10.0.3.58 -Parallel -ThrottleLimit 200 -ValidateForward -Colorize -OutputCsv .\hostnames.csv

.EXAMPLE
    .\Resolve-IPs-Parallel-v3.ps1 -InputPath .\ips.txt -DnsServer 10.0.3.58 -IncludeUnreachable -ValidateForward -Colorize
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [string[]] $IPAddress,

    [string]   $InputPath,
    [string]   $DnsServer          = '',
    [int]      $TimeoutMs          = 5000,
    [int]      $PingCount          = 1,
    [int]      $PingTimeoutMs      = 1000,
    [switch]   $Parallel,
    [int]      $ThrottleLimit      = 100,
    [string]   $OutputCsv          = '',
    [switch]   $OnlyResolved,
    [switch]   $IncludeUnreachable,
    [switch]   $ValidateForward,
    [switch]   $CaptureBothFamilies,
    [switch]   $Colorize
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $script:_pipelineIPs = [System.Collections.Generic.List[string]]::new()
}

process {
    if ($IPAddress) {
        foreach ($ip in $IPAddress) { $script:_pipelineIPs.Add($ip) }
    }
}

end {

    # ════════════════════════════════════════════════════════════════
    # 1. BUILD MASTER IP LIST
    # ════════════════════════════════════════════════════════════════
    $rawList = [System.Collections.Generic.List[string]]::new()
    foreach ($ip in $script:_pipelineIPs) { $rawList.Add($ip) }

    if ($InputPath -ne '') {
        if (-not (Test-Path -LiteralPath $InputPath)) {
            throw "InputPath not found: '$InputPath'"
        }
        foreach ($line in (Get-Content -LiteralPath $InputPath)) { $rawList.Add($line) }
    }

    if ($rawList.Count -eq 0) {
        Write-Error 'No IP addresses provided. Use -IPAddress, pipeline, or -InputPath.'
        return
    }

    $seen   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ipList = [System.Collections.Generic.List[string]]::new()
    foreach ($raw in $rawList) {
        $trimmed = $raw.Trim()
        if ($trimmed -ne '' -and $seen.Add($trimmed)) { $ipList.Add($trimmed) }
    }

    # ════════════════════════════════════════════════════════════════
    # 2. SERIAL WORKER FUNCTION
    # ════════════════════════════════════════════════════════════════
    function Invoke-ResolveOne {
        param(
            [string] $ip,
            [string] $DnsServer,
            [int]    $PingCount,
            [bool]   $IncludeUnreachable,
            [bool]   $ValidateForward,
            [bool]   $CaptureBothFamilies
        )

        # ── Parse IP ─────────────────────────────────────────────
        $parsedIP = $null
        try { $parsedIP = [System.Net.IPAddress]::Parse($ip) }
        catch {
            return [pscustomobject]@{
                IP=''; Reachable=$false; PingRttMs=$null; Hostname=$null
                SuccessPTR=$false; Method=$null; Error='Invalid IP format'
                ReverseZone=$null; ForwardChecked=$false; ForwardMatch=$null
                FwdA=$null; FwdAAAA=$null; CanonicalName=$null; RoundTripOK=$false
            } | Select-Object @{N='IP';E={$ip}},Reachable,PingRttMs,Hostname,
                SuccessPTR,Method,Error,ReverseZone,ForwardChecked,ForwardMatch,
                FwdA,FwdAAAA,CanonicalName,RoundTripOK
        }

        $isIPv6 = $parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6

        # ── Reverse zone ─────────────────────────────────────────
        $reverseZone = $null
        try {
            if (-not $isIPv6) {
                $o = $parsedIP.ToString() -split '\.'
                $reverseZone = "$($o[2]).$($o[1]).$($o[0]).in-addr.arpa"
            }
            else {
                $nibStr = ($parsedIP.GetAddressBytes() | ForEach-Object { $_.ToString('x2') }) -join ''
                $nibArr = $nibStr.ToCharArray()
                [Array]::Reverse($nibArr)
                $reverseZone = ($nibArr -join '.') + '.ip6.arpa'
            }
        }
        catch { }

        # ── Ping ─────────────────────────────────────────────────
        # -TimeoutMilliseconds and -TimeOutSec are absent when PS7 loads
        # the legacy Windows PowerShell DnsClient/NetTCPIP module.
        # Use -Count only; rely on try/catch for failure handling.
        $reachable = $false
        $pingRttMs = $null
        try {
            $pr = Test-Connection -TargetName $ip -Count $PingCount -ErrorAction SilentlyContinue
            if ($pr) {
                $hits = @($pr | Where-Object { $_.Status -eq 'Success' })
                $reachable = $hits.Count -gt 0
                if ($reachable) {
                    $rtts = $hits | ForEach-Object { $_.Latency }
                    if ($rtts) { $pingRttMs = [Math]::Round(($rtts | Measure-Object -Average).Average, 1) }
                }
            }
        }
        catch {
            # Fallback for PS 5.1 where -TargetName may not exist
            try {
                $reachable = [bool](Test-Connection -ComputerName $ip -Count $PingCount -Quiet -ErrorAction SilentlyContinue)
            }
            catch { $reachable = $false }
        }

        if (-not $reachable -and -not $IncludeUnreachable) {
            return [pscustomobject]@{
                IP             = $ip
                Reachable      = $false
                PingRttMs      = $null
                Hostname       = $null
                SuccessPTR     = $false
                Method         = $null
                Error          = 'Skipped due to ping failure'
                ReverseZone    = $reverseZone
                ForwardChecked = $false
                ForwardMatch   = $null
                FwdA           = $null
                FwdAAAA        = $null
                CanonicalName  = $null
                RoundTripOK    = $false
            }
        }

        # ── PTR lookup ───────────────────────────────────────────
        $hostname   = $null
        $successPTR = $false
        $method     = $null
        $errMsg     = $null

        $dnsArgs = @{ Name=$ip; Type='PTR'; ErrorAction='Stop' }
        if ($DnsServer -ne '') { $dnsArgs['Server'] = $DnsServer }

        try {
            $ptrResult = Resolve-DnsName @dnsArgs
            $ptrRecord = $ptrResult | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1
            if ($ptrRecord) {
                $hostname   = $ptrRecord.NameHost.TrimEnd('.')
                $successPTR = $true
                $method     = 'Resolve-DnsName'
            }
            else { $errMsg = 'PTR query returned no PTR record' }
        }
        catch { $errMsg = $_.Exception.Message }

        # ── Forward validation ────────────────────────────────────
        $forwardChecked = $false
        $forwardMatch   = $null
        $fwdA           = $null
        $fwdAAAA        = $null
        $canonicalName  = $null

        if ($ValidateForward -and $successPTR -and $hostname) {
            $forwardChecked = $true
            $fwdBase = @{ Name=$hostname; ErrorAction='SilentlyContinue' }
            if ($DnsServer -ne '') { $fwdBase['Server'] = $DnsServer }

            try {
                $cnArgs = $fwdBase.Clone(); $cnArgs['Type'] = 'CNAME'
                $cnResult = Resolve-DnsName @cnArgs
                $cname = $cnResult | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
                if ($cname) { $canonicalName = $cname.NameHost.TrimEnd('.') }
            }
            catch { }

            try {
                $aArgs = $fwdBase.Clone(); $aArgs['Type'] = 'A'
                $aResult = Resolve-DnsName @aArgs
                $aList = ($aResult | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) -join ';'
                $fwdA  = if ($aList -ne '') { $aList } else { $null }
            }
            catch { }

            if ($isIPv6 -or $CaptureBothFamilies) {
                try {
                    $a4Args = $fwdBase.Clone(); $a4Args['Type'] = 'AAAA'
                    $a4Result = Resolve-DnsName @a4Args
                    $a4List = ($a4Result | Where-Object { $_.Type -eq 'AAAA' } | ForEach-Object { $_.IPAddress }) -join ';'
                    $fwdAAAA = if ($a4List -ne '') { $a4List } else { $null }
                }
                catch { }
            }

            if (-not $isIPv6) {
                $forwardMatch = ($null -ne $fwdA) -and (($fwdA -split ';') -contains $ip)
            }
            else {
                $forwardMatch = ($null -ne $fwdAAAA) -and (($fwdAAAA -split ';') -contains $ip)
            }
        }

        $roundTripOK = if ($ValidateForward) {
            $successPTR -and $forwardChecked -and ($forwardMatch -eq $true)
        }
        else { $successPTR }

        return [pscustomobject]@{
            IP             = $ip
            Reachable      = $reachable
            PingRttMs      = $pingRttMs
            Hostname       = $hostname
            SuccessPTR     = $successPTR
            Method         = $method
            Error          = $errMsg
            ReverseZone    = $reverseZone
            ForwardChecked = $forwardChecked
            ForwardMatch   = $forwardMatch
            FwdA           = $fwdA
            FwdAAAA        = $fwdAAAA
            CanonicalName  = $canonicalName
            RoundTripOK    = $roundTripOK
        }
    }

    # ════════════════════════════════════════════════════════════════
    # 3. VERSION CHECK + DISPATCH
    # ════════════════════════════════════════════════════════════════
    $isPSv7 = $PSVersionTable.PSVersion.Major -ge 7

    if ($Parallel -and -not $isPSv7) {
        Write-Warning '-Parallel requested but PowerShell version is less than 7. Running serially.'
    }

    $useParallel          = $Parallel -and $isPSv7
    $bIncludeUnreachable  = [bool]$IncludeUnreachable
    $bValidateForward     = [bool]$ValidateForward
    $bCaptureBothFamilies = [bool]$CaptureBothFamilies
    $sDnsServer           = $DnsServer
    $iPingCount           = $PingCount

    # ── PARALLEL PATH (PS 7+) ─────────────────────────────────────
    # Worker logic inlined - scriptblock variables are NOT passable via
    # $using: in ForEach-Object -Parallel. Only primitives cross safely.
    $results = if ($useParallel) {

        $ipList | ForEach-Object -Parallel {

            $ip                  = $_
            $DnsServer           = $using:sDnsServer
            $PingCount           = $using:iPingCount
            $IncludeUnreachable  = $using:bIncludeUnreachable
            $ValidateForward     = $using:bValidateForward
            $CaptureBothFamilies = $using:bCaptureBothFamilies

            # Parse IP
            $parsedIP = $null
            try { $parsedIP = [System.Net.IPAddress]::Parse($ip) }
            catch {
                [pscustomobject]@{
                    IP=$ip; Reachable=$false; PingRttMs=$null; Hostname=$null
                    SuccessPTR=$false; Method=$null; Error='Invalid IP format'
                    ReverseZone=$null; ForwardChecked=$false; ForwardMatch=$null
                    FwdA=$null; FwdAAAA=$null; CanonicalName=$null; RoundTripOK=$false
                }
                return
            }

            $isIPv6 = $parsedIP.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6

            # Reverse zone
            $reverseZone = $null
            try {
                if (-not $isIPv6) {
                    $o = $parsedIP.ToString() -split '\.'
                    $reverseZone = "$($o[2]).$($o[1]).$($o[0]).in-addr.arpa"
                }
                else {
                    $nibStr = ($parsedIP.GetAddressBytes() | ForEach-Object { $_.ToString('x2') }) -join ''
                    $nibArr = $nibStr.ToCharArray()
                    [Array]::Reverse($nibArr)
                    $reverseZone = ($nibArr -join '.') + '.ip6.arpa'
                }
            }
            catch { }

            # Ping - no -TimeoutMilliseconds (incompatible with legacy DnsClient module)
            $reachable = $false
            $pingRttMs = $null
            try {
                $pr = Test-Connection -TargetName $ip -Count $PingCount -ErrorAction SilentlyContinue
                if ($pr) {
                    $hits = @($pr | Where-Object { $_.Status -eq 'Success' })
                    $reachable = $hits.Count -gt 0
                    if ($reachable) {
                        $rtts = $hits | ForEach-Object { $_.Latency }
                        if ($rtts) { $pingRttMs = [Math]::Round(($rtts | Measure-Object -Average).Average, 1) }
                    }
                }
            }
            catch {
                try {
                    $reachable = [bool](Test-Connection -ComputerName $ip -Count $PingCount -Quiet -ErrorAction SilentlyContinue)
                }
                catch { $reachable = $false }
            }

            if (-not $reachable -and -not $IncludeUnreachable) {
                [pscustomobject]@{
                    IP=$ip; Reachable=$false; PingRttMs=$null; Hostname=$null
                    SuccessPTR=$false; Method=$null; Error='Skipped due to ping failure'
                    ReverseZone=$reverseZone; ForwardChecked=$false; ForwardMatch=$null
                    FwdA=$null; FwdAAAA=$null; CanonicalName=$null; RoundTripOK=$false
                }
                return
            }

            # PTR lookup - no -TimeOutSec (incompatible with legacy DnsClient module)
            $hostname   = $null
            $successPTR = $false
            $method     = $null
            $errMsg     = $null

            $dnsArgs = @{ Name=$ip; Type='PTR'; ErrorAction='Stop' }
            if ($DnsServer -ne '') { $dnsArgs['Server'] = $DnsServer }

            try {
                $ptrResult = Resolve-DnsName @dnsArgs
                $ptrRecord = $ptrResult | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1
                if ($ptrRecord) {
                    $hostname   = $ptrRecord.NameHost.TrimEnd('.')
                    $successPTR = $true
                    $method     = 'Resolve-DnsName'
                }
                else { $errMsg = 'PTR query returned no PTR record' }
            }
            catch { $errMsg = $_.Exception.Message }

            # Forward validation
            $forwardChecked = $false
            $forwardMatch   = $null
            $fwdA           = $null
            $fwdAAAA        = $null
            $canonicalName  = $null

            if ($ValidateForward -and $successPTR -and $hostname) {
                $forwardChecked = $true
                $fwdBase = @{ Name=$hostname; ErrorAction='SilentlyContinue' }
                if ($DnsServer -ne '') { $fwdBase['Server'] = $DnsServer }

                try {
                    $cnArgs = $fwdBase.Clone(); $cnArgs['Type'] = 'CNAME'
                    $cnResult = Resolve-DnsName @cnArgs
                    $cname = $cnResult | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
                    if ($cname) { $canonicalName = $cname.NameHost.TrimEnd('.') }
                }
                catch { }

                try {
                    $aArgs = $fwdBase.Clone(); $aArgs['Type'] = 'A'
                    $aResult = Resolve-DnsName @aArgs
                    $aList = ($aResult | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) -join ';'
                    $fwdA  = if ($aList -ne '') { $aList } else { $null }
                }
                catch { }

                if ($isIPv6 -or $CaptureBothFamilies) {
                    try {
                        $a4Args = $fwdBase.Clone(); $a4Args['Type'] = 'AAAA'
                        $a4Result = Resolve-DnsName @a4Args
                        $a4List = ($a4Result | Where-Object { $_.Type -eq 'AAAA' } | ForEach-Object { $_.IPAddress }) -join ';'
                        $fwdAAAA = if ($a4List -ne '') { $a4List } else { $null }
                    }
                    catch { }
                }

                if (-not $isIPv6) {
                    $forwardMatch = ($null -ne $fwdA) -and (($fwdA -split ';') -contains $ip)
                }
                else {
                    $forwardMatch = ($null -ne $fwdAAAA) -and (($fwdAAAA -split ';') -contains $ip)
                }
            }

            $roundTripOK = if ($ValidateForward) {
                $successPTR -and $forwardChecked -and ($forwardMatch -eq $true)
            }
            else { $successPTR }

            [pscustomobject]@{
                IP             = $ip
                Reachable      = $reachable
                PingRttMs      = $pingRttMs
                Hostname       = $hostname
                SuccessPTR     = $successPTR
                Method         = $method
                Error          = $errMsg
                ReverseZone    = $reverseZone
                ForwardChecked = $forwardChecked
                ForwardMatch   = $forwardMatch
                FwdA           = $fwdA
                FwdAAAA        = $fwdAAAA
                CanonicalName  = $canonicalName
                RoundTripOK    = $roundTripOK
            }

        } -ThrottleLimit $ThrottleLimit

    }
    else {
        # ── SERIAL PATH ───────────────────────────────────────────
        $ipList | ForEach-Object {
            Invoke-ResolveOne `
                -ip                  $_ `
                -DnsServer           $sDnsServer `
                -PingCount           $iPingCount `
                -IncludeUnreachable  $bIncludeUnreachable `
                -ValidateForward     $bValidateForward `
                -CaptureBothFamilies $bCaptureBothFamilies
        }
    }

    # ════════════════════════════════════════════════════════════════
    # 4. FILTER
    # ════════════════════════════════════════════════════════════════
    if ($OnlyResolved) {
        $results = $results | Where-Object { $_.SuccessPTR -eq $true }
    }

    # ════════════════════════════════════════════════════════════════
    # 5. SORT BY IP
    # ════════════════════════════════════════════════════════════════
    $results = $results | Sort-Object {
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($_.IP, [ref]$parsed)) {
            $bytes  = $parsed.GetAddressBytes()
            $padded = [byte[]]::new(16)
            [Array]::Copy($bytes, 0, $padded, 16 - $bytes.Length, $bytes.Length)
            [System.BitConverter]::ToString($padded)
        }
        else { $_.IP }
    }

    # ════════════════════════════════════════════════════════════════
    # 6. CSV EXPORT
    # ════════════════════════════════════════════════════════════════
    if ($OutputCsv -ne '') {
        $results | Export-Csv -LiteralPath $OutputCsv -Encoding UTF8 -NoTypeInformation -Force
        Write-Verbose "Results exported to: $OutputCsv"
    }

    # ════════════════════════════════════════════════════════════════
    # 7. OUTPUT
    # ════════════════════════════════════════════════════════════════
    if ($Colorize) {

        $cols = @(
            @{ H='IP';        W=15 }
            @{ H='Reach';     W= 6 }
            @{ H='RTTms';     W= 6 }
            @{ H='Hostname';  W=40 }
            @{ H='PTR';       W= 3 }
            @{ H='FwdChk';    W= 6 }
            @{ H='FwdMatch';  W= 8 }
            @{ H='RoundTrip'; W= 9 }
            @{ H='Error';     W=50 }
        )

        $headerLine = ''; foreach ($c in $cols) { $headerLine += $c.H.PadRight($c.W) }
        Write-Host $headerLine -ForegroundColor Cyan

        $sepLine = ''; foreach ($c in $cols) { $sepLine += ('-' * $c.W) }
        Write-Host $sepLine -ForegroundColor DarkGray

        foreach ($row in $results) {

            $color = if ($row.RoundTripOK) { 'Green' }
                     elseif ($row.SuccessPTR -and (-not $row.ForwardChecked -or $row.ForwardMatch -ne $true)) { 'Yellow' }
                     elseif (-not $row.Reachable) { 'DarkGray' }
                     else { 'Red' }

            $reach    = if ($row.Reachable)              { 'Yes'  } else { 'No'    }
            $rtt      = if ($null -ne $row.PingRttMs)    { $row.PingRttMs.ToString() } else { '-' }
            $hostStr  = if ($row.Hostname)               { $row.Hostname } else { '-' }
            $ptr      = if ($row.SuccessPTR)             { 'Yes'  } else { 'No'    }
            $fwdChk   = if ($row.ForwardChecked)         { 'Yes'  } else { 'No'    }
            $fwdMatch = if ($null -eq $row.ForwardMatch) { 'N/A'  } elseif ($row.ForwardMatch) { 'True' } else { 'False' }
            $rt       = if ($row.RoundTripOK)            { 'OK'   } else { 'FAIL'  }
            $errTxt   = if ($row.Error)                  { $row.Error } else { '' }

            $line  = $row.IP.PadRight($cols[0].W)
            $line += $reach.PadRight($cols[1].W)
            $line += $rtt.PadRight($cols[2].W)
            $hT    = if ($hostStr.Length -gt $cols[3].W) { $hostStr.Substring(0,$cols[3].W-1)+'~' } else { $hostStr }
            $line += $hT.PadRight($cols[3].W)
            $line += $ptr.PadRight($cols[4].W)
            $line += $fwdChk.PadRight($cols[5].W)
            $line += $fwdMatch.PadRight($cols[6].W)
            $line += $rt.PadRight($cols[7].W)
            $eT    = if ($errTxt.Length -gt $cols[8].W) { $errTxt.Substring(0,$cols[8].W-1)+'~' } else { $errTxt }
            $line += $eT.PadRight($cols[8].W)

            Write-Host $line -ForegroundColor $color
        }
    }
    else {
        $results
    }

}
