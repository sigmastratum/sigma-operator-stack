param([string]$Project = (Get-Location).Path)
$ErrorActionPreference = "Stop"
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 (Join-Path $PSScriptRoot "native-smoke") $Project
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python (Join-Path $PSScriptRoot "native-smoke") $Project
} else {
    Write-Error "SOS_ALPHA_PYTHON_MISSING"
    exit 2
}
exit $LASTEXITCODE
