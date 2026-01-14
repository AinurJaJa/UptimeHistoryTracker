<#
.SYNOPSIS
    Скрипт для сбора информации о времени работы серверов
.DESCRIPTION
    Проверяет доступность серверов и собирает информацию об uptime
    через различные методы (WMI, CIM, Registry, SystemInfo)
.VERSION
    1.1
.AUTHOR
    System Administrator
#>

# Script parameters
param (
    [string]$OutputDirectory = "C:\Logs\Uptime",
    [string]$OutputFileName = "Uptime_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [int]$PingTimeout = 1000,  # Таймаут пинга в мс (было 3 сек по умолчанию)
    [switch]$SkipADSearch,      # Пропустить поиск в AD
    [string[]]$ComputerList     # Ручной список компьютеров
)

$LogFile = Join-Path -Path $OutputDirectory -ChildPath "Uptime_Script_$(Get-Date -Format 'yyyyMMdd').log"
$OutputFile = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    
    switch ($Level) {
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "INFO"    { Write-Host $logMessage -ForegroundColor Cyan }
        default   { Write-Host $logMessage -ForegroundColor Gray }
    }
    
    try {
        Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
    }
}

function Test-WMIPort {
    param([string]$ComputerName)
    
    try {
        $tcpClient = New-Object Net.Sockets.TcpClient
        $result = $tcpClient.BeginConnect($ComputerName, 135, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne(2000) # Уменьшили до 2 секунд
        if ($success) {
            $tcpClient.EndConnect($result)
            $tcpClient.Close()
            return $true
        }
        else {
            $tcpClient.Close()
            return $false
        }
    }
    catch {
        return $false
    }
    finally {
        if ($tcpClient -ne $null) {
            $tcpClient.Dispose()
        }
    }
}

function Test-ServerOnline {
    param([string]$ComputerName)
    
    try {
        if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -TimeoutSeconds 1) {
            return $true
        }
    }
    catch {}
    
    try {
        $tcpClient = New-Object Net.Sockets.TcpClient
        $result = $tcpClient.BeginConnect($ComputerName, 445, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne(1000)
        if ($success) {
            $tcpClient.EndConnect($result)
            return $true
        }
    }
    catch {}
    finally {
        if ($tcpClient -ne $null) {
            $tcpClient.Dispose()
        }
    }
    
    return $false
}

function Get-ServerUptime {
    param([string]$ComputerName)
    
    $result = @{
        LastBootTime = $null
        Uptime = $null
        Method = $null
        Error = $null
        Online = $false
    }
    
    # Проверяем доступность сервера
    if (-not (Test-ServerOnline -ComputerName $ComputerName)) {
        $result.Error = "Server not responding"
        return $result
    }
    
    $result.Online = $true
    
    # Проверяем доступность порта WMI
    if (-not (Test-WMIPort -ComputerName $ComputerName)) {
        $result.Error = "WMI port (135) not accessible"
        return $result
    }
    
    # Пробуем разные методы по порядку предпочтения
    $methods = @(
        @{Name = "CIM"; Script = {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $os.LastBootUpTime
        }},
        @{Name = "WMI"; Script = {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $os.ConvertToDateTime($os.LastBootUpTime)
        }},
        @{Name = "SystemInfo"; Script = {
            $sysinfo = systeminfo /s $ComputerName 2>$null | Select-String "System Boot Time"
            if ($sysinfo) {
                $bootTimeString = ($sysinfo -split ":", 2)[1].Trim()
                [DateTime]::Parse($bootTimeString)
            }
            else { throw "No boot time info" }
        }}
    )
    
    foreach ($method in $methods) {
        try {
            $lastBootTime = & $method.Script
            if ($lastBootTime) {
                $result.LastBootTime = $lastBootTime
                $result.Uptime = (Get-Date) - $lastBootTime
                $result.Method = $method.Name
                return $result
            }
        }
        catch {
            $result.Error = if ($result.Error) { 
                "$($result.Error) | $($method.Name): $($_.Exception.Message)"
            } else {
                "$($method.Name): $($_.Exception.Message)"
            }
        }
    }
    
    return $result
}

if (-not (Test-Path -Path $OutputDirectory)) {
    try {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        Write-Log "Directory created: $OutputDirectory" -Level "SUCCESS"
    }
    catch {
        Write-Log "Error creating directory: $_" -Level "ERROR"
        exit 1
    }
}

try {
    Get-ChildItem -Path $OutputDirectory -Filter "Uptime_Script_*.log" | 
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | 
        Remove-Item -Force -ErrorAction SilentlyContinue
}
catch {}

Write-Log "=== Uptime Check Script started ===" -Level "INFO"

if ($ComputerList) {
    Write-Log "Using manual computer list" -Level "INFO"
    $servers = $ComputerList | ForEach-Object {
        [PSCustomObject]@{
            Name = $_
            DNSHostName = $_
            OperatingSystem = "Unknown"
        }
    }
}
elseif (-not $SkipADSearch) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "ActiveDirectory module loaded successfully" -Level "SUCCESS"
        
        Write-Log "Search for computers in AD..." -Level "INFO"

        $searchBases = @(
            "OU=Servers,DC=domain,DC=com",
            "OU=Windows Servers,DC=domain,DC=com",
            "CN=Computers,DC=domain,DC=com"
        )
        
        $allServers = @()
        foreach ($searchBase in $searchBases) {
            try {
                $found = Get-ADComputer -Filter * -SearchBase $searchBase -SearchScope Subtree `
                        -Properties Name, LastLogonDate, OperatingSystem, Enabled -ErrorAction SilentlyContinue |
                        Where-Object {$_.Enabled -eq $true} |
                        Select-Object Name, OperatingSystem, @{Name="DNSHostName"; Expression={$_.Name}}
                
                if ($found) {
                    $allServers += $found
                    Write-Log "Found $($found.Count) servers in $searchBase" -Level "INFO"
                }
            }
            catch {
                Write-Log "Cannot search in $searchBase: $_" -Level "WARNING"
            }
        }

        $servers = $allServers | Sort-Object Name -Unique
        
        Write-Log "Total unique servers found: $($servers.Count)" -Level "INFO"

        if ($servers.Count -eq 0) {
            Write-Log "Warning: No servers found. Try using -ComputerList parameter" -Level "WARNING"
            exit 1
        }
    }
    catch {
        Write-Log "ActiveDirectory module not found or error: $_" -Level "ERROR"
        Write-Log "Install RSAT or use -ComputerList parameter" -Level "WARNING"
        exit 1
    }
}
else {
    Write-Log "AD search skipped. No computers to check." -Level "WARNING"
    exit 0
}

param (
    [switch]$VerboseLogging
)

$results = @()
$onlineCount = 0
$offlineCount = 0
$errorCount = 0
$totalServers = $servers.Count
$currentServer = 0
$scriptStart = Get-Date

Write-Log "Starting server availability check..." -Level "INFO"
Write-Log "Servers to check: $totalServers" -Level "INFO"
Write-Log "Ping timeout: ${PingTimeout}ms" -Level "INFO"
Write-Log "------------------------------------" -Level "INFO"

if (-not (Test-Path -Path $OutputDirectory -PathType Container)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    Write-Log "Created output directory: $OutputDirectory" -Level "INFO"
}

if ($PSVersionTable.PSVersion.Major -ge 7 -and $totalServers -gt 10) {
    Write-Log "Using parallel processing (PowerShell 7+)" -Level "INFO"
    
    $results = $servers | ForEach-Object -Parallel {
        $serverObj = $_
        $server = $serverObj.Name
        $osType = $serverObj.OperatingSystem
        $function:Test-ServerOnline = $using:function:Test-ServerOnline
        $function:Test-WMIPort = $using:function:Test-WMIPort
        $function:Get-ServerUptime = $using:function:Get-ServerUptime

        $online = Test-ServerOnline -ComputerName $server -Timeout 5000
        $result = [PSCustomObject]@{
            ServerName    = $server
            Status        = "Checking"
            LastBootTime  = "N/A"
            Uptime        = "N/A"
            CheckDate     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            OSType        = $osType
            PingResponse  = $online
            Method        = "N/A"
        }
        
        if ($online) {
            try {
                $uptimeInfo = Get-ServerUptime -ComputerName $server -Timeout 10000
            }
            catch {
                $uptimeInfo = [PSCustomObject]@{
                    Uptime      = $null
                    LastBootTime = $null
                    Method      = "Error"
                    Error       = $_.Exception.Message
                    Online      = $false
                }
                Write-Log "$server : WMI/RPC error: $($_.Exception.Message)" -Level "WARNING"
            }

            if ($uptimeInfo.Uptime) {
                $uptimeString = "{0}d {1}h {2}m" -f $uptimeInfo.Uptime.Days, $uptimeInfo.Uptime.Hours, $uptimeInfo.Uptime.Minutes
                $result.Status = "Online"
                $result.Uptime = $uptimeString
                $result.LastBootTime = if ($uptimeInfo.LastBootTime) { 
                    $uptimeInfo.LastBootTime.ToString("yyyy-MM-dd HH:mm:ss")
                } else { "N/A" }
                $result.Method = $uptimeInfo.Method
                
                Write-Host "$server : Online (Uptime: $uptimeString via $($uptimeInfo.Method))" -ForegroundColor Green
            }
            else {
                $result.Status = if ($uptimeInfo.Online) { "Access Denied" } else { "Offline" }
                Write-Host "$server : $($result.Status) ($($uptimeInfo.Error))" -ForegroundColor Yellow
            }
        }
        else {
            $result.Status = "Offline"
            Write-Host "$server : Offline" -ForegroundColor Red
        }
        
        $result
    } -ThrottleLimit 10
    $onlineCount = ($results | Where-Object { $_.Status -eq "Online" }).Count
    $offlineCount = ($results | Where-Object { $_.Status -eq "Offline" }).Count
    $errorCount = ($results | Where-Object { $_.Status -notin @("Online", "Offline") }).Count
}
else {
    foreach ($serverObj in $servers) {
        $currentServer++
        $server = $serverObj.Name
        $osType = $serverObj.OperatingSystem

        $percent = [math]::Round(($currentServer / $totalServers) * 100, 0)
        $elapsed = (Get-Date) - $scriptStart
        $avgTimePerServer = $elapsed.TotalSeconds / $currentServer
        $estimatedTotal = $avgTimePerServer * $totalServers
        $estimatedEnd = (Get-Date).AddSeconds($estimatedTotal - $elapsed.TotalSeconds)

        Write-Progress -Activity "Checking servers" `
            -Status "Processing $server ($currentServer of $totalServers) – $percent% – ETA: $($estimatedEnd.ToString('HH:mm:ss'))" `
            -PercentComplete $percent

        Write-Host "[$currentServer/$totalServers] Checking server: $server" -ForegroundColor Gray

        $online = Test-ServerOnline -ComputerName $server -Timeout 5000

        try { 
            $uptimeInfo = Get-ServerUptime -ComputerName $server -Timeout 10000
        }
        catch {
            $uptimeInfo = [PSCustomObject]@{
                Uptime      = $null
                LastBootTime = $null
                Method      = "Error"
                Error       = $_.Exception.Message
                Online      = $false
            }
            Write-Log "$server : WMI/RPC error: $($_.Exception.Message)" -Level "WARNING"
        }

        if ($online -and $uptimeInfo.Uptime) {
            $uptimeString = "{0}d {1}h {2}m" -f $uptimeInfo.Uptime.Days, $uptimeInfo.Uptime.Hours, $uptimeInfo.Uptime.Minutes
            $status = "Online"
            $onlineCount++
            $method = $uptimeInfo.Method

            Write-Log "$server : Online (Uptime: $uptimeString via $method)" -Level "SUCCESS"
        }
        elseif ($online) {
            $status = if ($uptimeInfo.Online) { "Access Denied" } else { "Offline" }
            $uptimeString = "N/A"
            $method = "N/A"
            $errorCount++

            Write-Log "$server : $status ($($uptimeInfo.Error))" -Level "WARNING"
        }
        else {
            $status = "Offline"
            $uptimeString = "N/A"
            $lastBootTime = "N/A"
            $method = "N/A"
            $offlineCount++

            Write-Log "$server : Offline" -Level "ERROR"
        }

        $lastBootTime = if ($uptimeInfo.LastBootTime) {
            $uptimeInfo.LastBootTime.ToString("yyyy-MM-dd HH:mm:ss")
        } else {
            "N/A"
        }

        $results += [PSCustomObject]@{
            ServerName    = $server
            Status        = $status
            LastBootTime  = $lastBootTime
            Uptime        = $uptimeString
            CheckDate     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            OSType        = $osType
            PingResponse  = $online
            Method        = $method
        }
    }
    Write-Progress -Activity "Checking servers" -Completed
}

Write-Log "------------------------------------" -Level "INFO"
Write-Log "Check completed. Summary:" -Level "INFO"
Write-Log "Total servers: $totalServers" -Level "INFO