#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Ophan API Gateway — Windows Installer
.DESCRIPTION
    Downloads and installs Ophan API Gateway from GitHub releases.
    Registers as a Windows Service via SCM.
.PARAMETER Version
    Release version to install (default: latest)
.PARAMETER InstallDir
    Installation directory (default: $env:ProgramFiles\Ophan)
.PARAMETER ConfigDir
    Configuration directory (default: $env:ProgramData\Ophan)
.EXAMPLE
    .\install.ps1
    .\install.ps1 -Version v0.1.0
    .\install.ps1 -InstallDir "D:\Ophan"
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$Version = "latest",

    [Parameter(Mandatory = $false)]
    [string]$InstallDir = "$env:ProgramFiles\Ophan",

    [Parameter(Mandatory = $false)]
    [string]$ConfigDir = "$env:ProgramData\Ophan\config",

    [Parameter(Mandatory = $false)]
    [string]$LogDir = "$env:ProgramData\Ophan\logs"
)

$Repo = "zsweiter/ophan"
$Arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "i686" }

# Resolve version
if ($Version -eq "latest") {
    Write-Host "Fetching latest release info ..."
    $api = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $api.tag_name
}
$Version = $Version.TrimStart('v')

$Package = "ophan-${Version}-windows-${Arch}.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/v${Version}/$Package"

# Temp directory
$TmpDir = Join-Path $env:TEMP "ophan-install-$([System.Guid]::NewGuid().ToString().Substring(0,8))"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    # Download
    Write-Host "⬇️  Downloading $Package ..."
    $zipPath = Join-Path $TmpDir $Package
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipPath -UseBasicParsing

    # Verify checksum
    try {
        $checksumUrl = "$DownloadUrl.sha256"
        $expected = (Invoke-WebRequest -Uri $checksumUrl -UseBasicParsing).Content.Trim().Split(' ')[0]
        $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
        if ($expected -ne $actual) {
            Write-Error "❌ Checksum verification failed"
            exit 1
        }
        Write-Host "✅ Checksum verified"
    } catch {
        Write-Warning "Checksum verification skipped (no checksum file)"
    }

    # Extract
    Write-Host "📦 Extracting ..."
    Expand-Archive -Path $zipPath -DestinationPath $TmpDir
    $extracted = Get-ChildItem -Path "$TmpDir\ophan-*" -Directory | Select-Object -First 1

    # Install binary
    Write-Host "🔧 Installing to $InstallDir ..."
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path "$($extracted.FullName)\ophan.exe" -Destination "$InstallDir\ophan.exe" -Force
    $binaryPath = "$InstallDir\ophan.exe"

    # Install config
    Write-Host "📄 Installing config to $ConfigDir ..."
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    if (Test-Path "$($extracted.FullName)\config") {
        Copy-Item -Path "$($extracted.FullName)\config\*" -Destination $ConfigDir -Recurse -Force
    }

    # Create log directory
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

    # Register Windows Service
    Write-Host "🛠️  Registering Windows Service ..."
    $serviceName = "Ophan"
    $serviceDisplayName = "Ophan API Gateway"

    if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
        Write-Host "Service already exists. Stopping and removing ..."
        Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName
        Start-Sleep -Seconds 2
    }

    New-Service -Name $serviceName `
        -DisplayName $serviceDisplayName `
        -Description "High-Performance Reverse Proxy, API Gateway and Load Balancer" `
        -BinaryPathName "`"$binaryPath`" -c `"$ConfigDir\master.conf`"" `
        -StartupType Automatic

    & sc.exe failure $serviceName reset=86400 actions=restart/5000/restart/10000/restart/30000

    Write-Host "✅ Service registered. Starting ..."
    Start-Service $serviceName

    Write-Host ""
    Write-Host "✅ Ophan v$Version installed successfully!"
    Write-Host "   Binary: $binaryPath"
    Write-Host "   Config: $ConfigDir"
    Write-Host "   Start:  Start-Service $serviceName"

} finally {
    Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
