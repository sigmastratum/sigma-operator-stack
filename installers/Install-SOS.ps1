param(
    [ValidateSet("install", "update", "remove")]
    [string]$Mode = "install",
    [string]$Project = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$Launcher = Join-Path $PSScriptRoot "start-sos-alpha"
$UvSource = Join-Path $PSScriptRoot "uv.exe"
$UvExpected = "965816e654d8fac650b282345c89c1daff16a0cfe45e9d2d2a8f5af3fed466a4"
$RuntimeRoot = Join-Path $env:LOCALAPPDATA "SigmaOperatorStack\runtime"
$Bootstrap = Join-Path $RuntimeRoot "bootstrap"
$Uv = Join-Path $Bootstrap "uv-0.12.6.exe"
$PythonRoot = Join-Path $RuntimeRoot "python"

if (-not (Test-Path -LiteralPath $UvSource -PathType Leaf)) {
    Write-Error "SOS_ALPHA_UV_BUNDLE_INVALID: the checked uv bootstrap binary is missing."
    exit 2
}
$Observed = (Get-FileHash -LiteralPath $UvSource -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Observed -ne $UvExpected) {
    Write-Error "SOS_ALPHA_UV_CHECKSUM_MISMATCH: do not continue with this bundle."
    exit 2
}

$RuntimeItem = Get-Item -LiteralPath $RuntimeRoot -Force -ErrorAction SilentlyContinue
if ($null -ne $RuntimeItem -and ($RuntimeItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    Write-Error "SOS_ALPHA_RUNTIME_COLLISION: the managed runtime root must not be a reparse point."
    exit 2
}
New-Item -ItemType Directory -Force -Path $Bootstrap, $PythonRoot, (Join-Path $RuntimeRoot "tools"), (Join-Path $RuntimeRoot "bin") | Out-Null
Copy-Item -LiteralPath $UvSource -Destination $Uv -Force

$env:UV_PYTHON_INSTALL_DIR = $PythonRoot
$env:UV_TOOL_DIR = Join-Path $RuntimeRoot "tools"
$env:UV_TOOL_BIN_DIR = Join-Path $RuntimeRoot "bin"
$env:UV_NO_CONFIG = "1"

$Python = (& $Uv python find --no-config --managed-python --no-python-downloads 3.12.14 2>$null | Select-Object -First 1)
$PythonFindStatus = $LASTEXITCODE
if ($PythonFindStatus -ne 0 -or [string]::IsNullOrWhiteSpace($Python)) {
    if ($Mode -eq "remove") {
        Write-Error "SOS_ALPHA_MANAGED_PYTHON_MISSING: removal cannot acquire a runtime from the network."
        exit 2
    }
    Write-Host "SOS acquisition: installing the pinned managed Python 3.12.14 runtime."
    & $Uv python install --no-config --no-progress --no-registry --install-dir $PythonRoot 3.12.14
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $Python = (& $Uv python find --no-config --managed-python --no-python-downloads 3.12.14 | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($Python)) {
        Write-Error "SOS_ALPHA_MANAGED_PYTHON_MISSING: the pinned managed runtime was not admitted."
        exit 2
    }
}

& $Python $Launcher --uv $Uv --mode $Mode $Project
$Status = $LASTEXITCODE

if ($Status -eq 0 -and $Mode -eq "remove") {
    $ExpectedRoot = Join-Path $env:LOCALAPPDATA "SigmaOperatorStack\runtime"
    if ($RuntimeRoot -ne $ExpectedRoot) {
        Write-Error "SOS_ALPHA_RUNTIME_REMOVE_REFUSED: managed runtime root is not exact."
        exit 2
    }
    Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force
}

exit $Status
