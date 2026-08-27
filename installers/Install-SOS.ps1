param(
    [ValidateSet("install", "update", "remove")]
    [string]$Mode = "install",
    [string]$Project = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$Launcher = Join-Path $PSScriptRoot "start-sos-alpha"

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $Launcher --mode $Mode $Project
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $Launcher --mode $Mode $Project
} else {
    Write-Error "SOS_ALPHA_PYTHON_MISSING: install Python 3.11 or 3.12 from python.org."
    exit 2
}

exit $LASTEXITCODE
