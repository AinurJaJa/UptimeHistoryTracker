# Script parameters
param (
    [string]$OutputDirectory = "C:\Logs\Uptime",
    [string]$OutputFileName = "Uptime_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$OutputFile = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName

if (-not (Test-Path -Path $OutputDirectory)) {
    try {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        Write-Host "Directory created $OutputDirectory" -ForegroundColor Green
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
    
    $servers = Get-ADComputer -Filter * -SearchBase "OU=Servers,DC=domain,DC=com" -SearchScope Subtree -Properties Name, LastLogonDate, OperatingSystem |
               Select-Object Name, OperatingSystem
               
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

Write-Host "Starting server availability check..." -ForegroundColor Cyan
Write-Host "------------------------------------" -ForegroundColor Cyan

foreach ($serverObj in $servers) {
    $server = $serverObj.Name
    $osType = $serverObj.OperatingSystem
    
    Write-Host "Checking server: $server" -ForegroundColor Gray

    $online = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
    
    if ($online) {
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $server -ErrorAction Stop

            $lastBootTime = $os.ConvertToDateTime($os.LastBootUpTime)
            $uptime = (Get-Date) - $lastBootTime
            $uptimeString = "{0} d. {1} h. {2} min." -f $uptime.Days, $uptime.Hours, $uptime.Minutes
            
            $status = "Online"
            $onlineCount++
            
            Write-Host "$server : Online (Uptime: $uptimeString)" -ForegroundColor Green
            
        }
        catch {
            $status = "WMI Error"
            $uptimeString = "N/A"
            $lastBootTime = "N/A"
            $errorCount++
            
            Write-Host "$server : Online (WMI Error: $($_.Exception.Message))" -ForegroundColor Yellow
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
    }
}

Write-Host "------------------------------------" -ForegroundColor Cyan
Write-Host "Check completed. Summary:" -ForegroundColor Cyan
Write-Host "Online: $onlineCount" -ForegroundColor Green
Write-Host "Offline: $offlineCount" -ForegroundColor Red
Write-Host "Errors: $errorCount" -ForegroundColor Yellow
try {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Host "The report was successfully saved: $OutputFile" -ForegroundColor Green
    Invoke-Item -Path $OutputDirectory
}
catch {
    Write-Host "Error saving report: $_" -ForegroundColor Red
    Write-Host "Check file permissions and disk space" -ForegroundColor Yellow
}


Write-Host "Script execution completed" -ForegroundColor Green