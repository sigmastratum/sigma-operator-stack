param([string]$Project = (Get-Location).Path)
$ErrorActionPreference = "Stop"
$RuntimeRoot = Join-Path $env:LOCALAPPDATA "SigmaOperatorStack\runtime"
$Uv = Join-Path $RuntimeRoot "bootstrap\uv-0.12.6.exe"
if (-not (Test-Path -LiteralPath $Uv -PathType Leaf)) {
    Write-Error "SOS_ALPHA_RUNTIME_MISSING: run Install-SOS.ps1 install first."
    exit 2
}
$env:UV_PYTHON_INSTALL_DIR = Join-Path $RuntimeRoot "python"
$env:UV_TOOL_DIR = Join-Path $RuntimeRoot "tools"
$env:UV_TOOL_BIN_DIR = Join-Path $RuntimeRoot "bin"
$env:UV_NO_CONFIG = "1"
$Python = (& $Uv python find --offline --no-config --managed-python --no-python-downloads 3.12.14 | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Python)) {
    Write-Error "SOS_ALPHA_MANAGED_PYTHON_MISSING"
    exit 2
}
& $Python (Join-Path $PSScriptRoot "native-smoke") --uv $Uv $Project
exit $LASTEXITCODE
