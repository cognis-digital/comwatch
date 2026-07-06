<#
.SYNOPSIS
    comwatch installer for Windows (PowerShell). Builds a self-contained binary
    and copies it to a bin directory, adding that directory to your user PATH.
.PARAMETER Prefix
    Install root. Defaults to $env:LOCALAPPDATA\Programs\comwatch.
.EXAMPLE
    ./install.ps1
#>
[CmdletBinding()]
param(
    [string] $Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\comwatch')
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Error "dotnet SDK not found. Install .NET 8: https://dotnet.microsoft.com/download"
    exit 1
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$binDir = Join-Path $Prefix 'bin'
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

Write-Host "building self-contained comwatch..."
dotnet publish (Join-Path $here 'comwatch.csproj') -c Release `
    -p:PublishSingleFile=true --self-contained true -r win-x64 -o (Join-Path $here 'dist') | Out-Null

$exe = Join-Path $here 'dist\comwatch.exe'
if (-not (Test-Path $exe)) { $exe = Join-Path $here 'dist\comwatch' }
Copy-Item $exe (Join-Path $binDir 'comwatch.exe') -Force

# Add to user PATH if missing.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$binDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$binDir", 'User')
    Write-Host "added $binDir to your user PATH (restart your shell to pick it up)"
}

Write-Host "installed: $(Join-Path $binDir 'comwatch.exe')"
Write-Host "try: comwatch --selftest"
