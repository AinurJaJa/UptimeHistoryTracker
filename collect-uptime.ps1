# Script parameters
param (
    [string]$OutputDirectory = "C:\Logs\Uptime",
    [string]$OutputFileName = "Uptime_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$OutputFile = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName

function Get-ServerUptime {
    param([string]$ComputerName)
    
    $result = @{
        LastBootTime = $null
        Uptime = $null
        Method = $null
        Error = $null
    }
    
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
        $result.LastBootTime = $os.ConvertToDateTime($os.LastBootUpTime)
        $result.Uptime = (Get-Date) - $result.LastBootTime
        $result.Method = "WMI"
        return $result
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
        $result.LastBootTime = $os.LastBootUpTime
        $result.Uptime = (Get-Date) - $result.LastBootTime
        $result.Method = "CIM"
        return $result
    }
    catch {
        $result.Error += " | CIM: $($_.Exception.Message)"
    }
    
    try {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
        $key = $reg.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        $installDate = $key.GetValue('InstallDate')
        
        if ($installDate) {
            $result.LastBootTime = [DateTime]::FromFileTime($installDate)
            $result.Uptime = (Get-Date) - $result.LastBootTime
            $result.Method = "Registry"
            return $result
        }
    }
    catch {
        $result.Error += " | Registry: $($_.Exception.Message)"
    }
    
    try {
        $sysinfo = systeminfo /s $ComputerName 2>$null | Select-String "System Boot Time"
        if ($sysinfo) {
            $bootTimeString = ($sysinfo -split ":", 2)[1].Trim()
            $result.LastBootTime = [DateTime]::Parse($bootTimeString)
            $result.Uptime = (Get-Date) - $result.LastBootTime
            $result.Method = "SystemInfo"
            return $result
        }
    }
    catch {
        $result.Error += " | SystemInfo: $($_.Exception.Message)"
    }
    
    return $result
}

if (-not (Test-Path -Path $OutputDirectory)) {
    try {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        Write-Host "Directory created: $OutputDirectory" -ForegroundColor Green
    }
    catch {
        Write-Host "Error creating directory: $_" -ForegroundColor Red
        exit 1
    }
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "ActiveDirectory module loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "ActiveDirectory module not found. Make sure RSAT is installed." -ForegroundColor Red
    Write-Host "Detailed error: $_" -ForegroundColor Yellow
    exit 1
}

try {
    Write-Host "Search for computers in AD..." -ForegroundColor Cyan
    
    $servers = Get-ADComputer -Filter * -SearchBase "OU=Servers,DC=domain,DC=com" -SearchScope Subtree -Properties Name, LastLogonDate, OperatingSystem, Enabled |
               Where-Object {$_.Enabled -eq $true} |
               Select-Object Name, OperatingSystem, @{Name="DNSHostName"; Expression={$_.Name}}
               
    Write-Host "Servers found: $($servers.Count)" -ForegroundColor Cyan

    if ($servers.Count -eq 0) {
        Write-Host "Warning: No servers found in specified OU. Check SearchBase parameter." -ForegroundColor Yellow
        exit 1
    }
}
catch {
    Write-Host "Error searching for computers in AD: $_" -ForegroundColor Red
    Write-Host "Check your domain connection and permissions" -ForegroundColor Yellow
    exit 1
}

$results = @()
$onlineCount = 0
$offlineCount = 0
$errorCount = 0
$totalServers = $servers.Count
$currentServer = 0

Write-Host "Starting server availability check..." -ForegroundColor Cyan
Write-Host "Servers to check: $totalServers" -ForegroundColor Cyan
Write-Host "------------------------------------" -ForegroundColor Cyan

foreach ($serverObj in $servers) {
    $currentServer++
    $server = $serverObj.Name
    $osType = $serverObj.OperatingSystem
    Write-Progress -Activity "Checking servers" -Status "Processing $server ($currentServer of $totalServers)" -PercentComplete (($currentServer / $totalServers) * 100)
    Write-Host "[$currentServer/$totalServers] Checking server: $server" -ForegroundColor Gray
    $online = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
    if ($online) {
        try {
            $uptimeInfo = Get-ServerUptime -ComputerName $server
            
            if ($uptimeInfo.Uptime) {
                $uptimeString = "{0}d {1}h {2}m" -f $uptimeInfo.Uptime.Days, $uptimeInfo.Uptime.Hours, $uptimeInfo.Uptime.Minutes
                $status = "Online"
                $onlineCount++
                
                Write-Host "$server : Online (Uptime: $uptimeString via $($uptimeInfo.Method))" -ForegroundColor Green
            }
            else {
                $status = "Access Denied"
                $uptimeString = "N/A"
                $lastBootTime = "N/A"
                $errorCount++
                
                Write-Host "$server : Online but cannot get uptime ($($uptimeInfo.Error))" -ForegroundColor Yellow
            }
            
            $lastBootTime = if ($uptimeInfo.LastBootTime) { $uptimeInfo.LastBootTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
            
        }
        catch {
            $status = "WMI Error"
            $uptimeString = "N/A"
            $lastBootTime = "N/A"
            $errorCount++
            
            Write-Host "$server : Online (Error: $($_.Exception.Message))" -ForegroundColor Yellow
        }
    }
    else {
        $status = "Offline"
        $uptimeString = "N/A"
        $lastBootTime = "N/A"
        $offlineCount++
        
        Write-Host "$server : Offline" -ForegroundColor Red
    }
    
    $results += [PSCustomObject]@{
        ServerName    = $server
        Status        = $status
        LastBootTime  = $lastBootTime
        Uptime        = $uptimeString
        CheckDate     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        OSType        = $osType
        PingResponse  = $online
    }
}
Write-Progress -Activity "Checking servers" -Completed
Write-Host "------------------------------------" -ForegroundColor Cyan
Write-Host "Check completed. Summary:" -ForegroundColor Cyan
Write-Host "Total servers: $totalServers" -ForegroundColor White
Write-Host "Online: $onlineCount" -ForegroundColor Green
Write-Host "Offline: $offlineCount" -ForegroundColor Red
Write-Host "With errors: $errorCount" -ForegroundColor Yellow
try {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Host "The report was successfully saved: $OutputFile" -ForegroundColor Green
    $results | Format-Table ServerName, Status, Uptime -AutoSize
    Invoke-Item -Path $OutputDirectory
}
catch {
    Write-Host "Error saving report: $_" -ForegroundColor Red
    Write-Host "Check file permissions and disk space" -ForegroundColor Yellow
}
Write-Host "Script execution completed" -ForegroundColor Green