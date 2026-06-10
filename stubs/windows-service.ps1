param(
    [Parameter(Mandatory = $false)]
    [string]$Action = "install",

    [Parameter(Mandatory = $false)]
    [string]$BinaryPath = "$env:ProgramFiles\Ophan\ophan.exe",

    [Parameter(Mandatory = $false)]
    [string]$ConfigDir = "$env:ProgramData\Ophan\config",

    [Parameter(Mandatory = $false)]
    [string]$LogDir = "$env:ProgramData\Ophan\logs"
)

$ServiceName = "Ophan"
$DisplayName = "Ophan API Gateway"
$Description = "High-Performance Reverse Proxy, API Gateway and Load Balancer"

function Install-Service {
    Write-Host "Installing Windows Service: $ServiceName"

    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        Write-Warning "Service '$ServiceName' already exists. Stopping and removing..."
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName
        Start-Sleep -Seconds 2
    }

    if (-not (Test-Path $BinaryPath)) {
        Write-Error "Binary not found at: $BinaryPath"
        exit 1
    }

    New-Service -Name $ServiceName `
        -DisplayName $DisplayName `
        -Description $Description `
        -BinaryPathName "`"$BinaryPath`" -c `"$ConfigDir\master.conf`"" `
        -StartupType Automatic

    # Recovery options: restart on failure
    sc.exe failure $ServiceName reset=86400 actions=restart/5000/restart/10000/restart/30000

    Write-Host "Service installed successfully."
    Start-Service $ServiceName
    Write-Host "Service started."
}

function Uninstall-Service {
    Write-Host "Uninstalling Windows Service: $ServiceName"
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName
    Write-Host "Service removed."
}

function Status-Service {
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        $svc = Get-Service $ServiceName
        Write-Host "Service: $ServiceName"
        Write-Host "Status : $($svc.Status)"
        Write-Host "Start  : $($svc.StartType)"
    } else {
        Write-Host "Service '$ServiceName' is not installed."
    }
}

switch ($Action) {
    "install"   { Install-Service }
    "uninstall" { Uninstall-Service }
    "status"    { Status-Service }
    default     { Write-Error "Unknown action: $Action. Use install, uninstall, or status."; exit 1 }
}
