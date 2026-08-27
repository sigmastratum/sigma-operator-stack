param([string]$Project = (Get-Location).Path)
$ErrorActionPreference = "Stop"
$Uv = Get-Command uv -ErrorAction SilentlyContinue
if (-not $Uv) {
    Write-Error "SOS_ALPHA_UV_MISSING: install uv from its official distribution."
    exit 2
}
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 (Join-Path $PSScriptRoot "native-smoke") --uv $Uv.Source $Project
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python (Join-Path $PSScriptRoot "native-smoke") --uv $Uv.Source $Project
} else {
    Write-Error "SOS_ALPHA_PYTHON_MISSING"
    exit 2
}
exit $LASTEXITCODE
