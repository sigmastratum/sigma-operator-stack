#requires -Version 5.1
<#
.SYNOPSIS
Starts the checked SOS alpha in a native WSL2 project workspace.

.DESCRIPTION
This launcher never installs WSL, elevates privileges, or uses a Windows-backed
mount as canonical SOS state. It imports one clean Git repository through a Git
bundle into the selected distribution's native Linux home, records a stable
mapping, runs the checked Linux launcher, and opens Codex in the same workspace.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Project,

    [string]$Distro = "Ubuntu",

    [string]$PrimaryAuthority,

    [switch]$PlanOnly,

    [switch]$NoOpenCodex
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Script:Contract = "sos_windows_wsl2_launcher_v1"
$Script:Version = "0.1.0a1"
$Script:Wheel = "sigma_operator_stack-0.1.0a1-py3-none-any.whl"
$Script:Sbom = "sigma-operator-stack-0.1.0a1.cdx.json"
$Script:ExpectedFiles = @(
    "START-HERE.md",
    "release-manifest.json",
    $Script:Sbom,
    "start-sos-alpha",
    "start-sos-windows.ps1",
    $Script:Wheel
)
$Script:MaxFileBytes = @{
    "START-HERE.md" = 262144
    "release-manifest.json" = 1048576
    "sigma-operator-stack-0.1.0a1.cdx.json" = 16777216
    "start-sos-alpha" = 1048576
    "start-sos-windows.ps1" = 1048576
    "sigma_operator_stack-0.1.0a1-py3-none-any.whl" = 67108864
}

function Stop-SosWindows {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Problem,
        [Parameter(Mandatory = $true)][string]$NextAction
    )
    [ordered]@{
        contract = $Script:Contract
        status = "blocked"
        failure_code = $Code
        problem = $Problem
        next_action = $NextAction
    } | ConvertTo-Json -Compress | Write-Host
    exit 2
}

function Invoke-CheckedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$Capture,
        [switch]$AllowFailure
    )
    if ($Capture) {
        $output = @(& $Executable @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
        $text = ($output | ForEach-Object { [string]$_ }) -join "`n"
        if (-not $AllowFailure -and $exitCode -ne 0) {
            throw "command_failed:$exitCode"
        }
        return [pscustomobject]@{ ExitCode = $exitCode; Output = $text.Trim() }
    }
    & $Executable @Arguments
    $exitCode = $LASTEXITCODE
    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "command_failed:$exitCode"
    }
    return $exitCode
}

function Invoke-Wsl {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$Capture,
        [switch]$AllowFailure
    )
    $wslArguments = @("-d", $Distro, "--exec") + $Arguments
    return Invoke-CheckedProcess -Executable $Script:Wsl -Arguments $wslArguments -Capture:$Capture -AllowFailure:$AllowFailure
}

function Test-SafeToken {
    param([Parameter(Mandatory = $true)][string]$Value)
    return $Value -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
}

function Get-ProjectId {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Distribution
    )
    $normalized = $Root.TrimEnd('\').ToLowerInvariant() + "`0" + $Distribution.ToLowerInvariant()
    $bytes = [Text.Encoding]::UTF8.GetBytes($normalized)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return (($hasher.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "").Substring(0, 16)
    }
    finally {
        $hasher.Dispose()
    }
}

function Read-ExactChecksums {
    param([Parameter(Mandatory = $true)][string]$Bundle)
    $checksumPath = Join-Path $Bundle "SHA256SUMS"
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        Stop-SosWindows "SOS_WINDOWS_BUNDLE_INCOMPLETE" "SHA256SUMS is missing." "Copy the complete alpha bundle again."
    }
    $checksumItem = Get-Item -LiteralPath $checksumPath -Force
    if (($checksumItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $checksumItem.Length -gt 1048576) {
        Stop-SosWindows "SOS_WINDOWS_CHECKSUMS_INVALID" "SHA256SUMS has an unsupported file type or size." "Copy the complete alpha bundle again."
    }
    $values = @{}
    foreach ($line in [IO.File]::ReadAllLines($checksumPath)) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})$') {
            Stop-SosWindows "SOS_WINDOWS_CHECKSUMS_INVALID" "SHA256SUMS has an unsupported record." "Copy the complete alpha bundle again."
        }
        if ($values.ContainsKey($Matches[2])) {
            Stop-SosWindows "SOS_WINDOWS_CHECKSUMS_INVALID" "SHA256SUMS contains a duplicate filename." "Copy the complete alpha bundle again."
        }
        $values[$Matches[2]] = $Matches[1]
    }
    $actualNames = @($values.Keys | Sort-Object)
    $expectedNames = @($Script:ExpectedFiles | Sort-Object)
    if (($actualNames -join "`n") -cne ($expectedNames -join "`n")) {
        Stop-SosWindows "SOS_WINDOWS_BUNDLE_INCOMPLETE" "The bundle inventory does not match this launcher." "Copy the complete alpha bundle again."
    }
    return $values
}

function Test-ExactBundle {
    param([Parameter(Mandatory = $true)][string]$Bundle)
    $checksums = Read-ExactChecksums $Bundle
    foreach ($name in $Script:ExpectedFiles) {
        $path = Join-Path $Bundle $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Stop-SosWindows "SOS_WINDOWS_BUNDLE_INCOMPLETE" "Bundle file '$name' is missing." "Copy the complete alpha bundle again."
        }
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-SosWindows "SOS_WINDOWS_BUNDLE_FILE_INVALID" "Bundle file '$name' is a reparse point." "Copy the complete alpha bundle again."
        }
        if ($item.Length -gt $Script:MaxFileBytes[$name]) {
            Stop-SosWindows "SOS_WINDOWS_BUNDLE_FILE_TOO_LARGE" "Bundle file '$name' exceeds its safety limit." "Copy the complete alpha bundle again."
        }
        $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($digest -cne $checksums[$name]) {
            Stop-SosWindows "SOS_WINDOWS_CHECKSUM_MISMATCH" "Checksum verification failed for '$name'." "Do not continue; copy the complete alpha bundle again."
        }
    }
    try {
        $manifest = Get-Content -LiteralPath (Join-Path $Bundle "release-manifest.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Stop-SosWindows "SOS_WINDOWS_MANIFEST_INVALID" "The release manifest is malformed." "Copy the complete alpha bundle again."
    }
    if (
        $manifest.contract -cne "sos_public_release_manifest_v1" -or
        $manifest.version -cne $Script:Version -or
        [string]$manifest.candidate -notmatch '^[0-9a-f]{40}$' -or
        [string]$manifest.tree -notmatch '^[0-9a-f]{40}$' -or
        $manifest.build.network_allowed -ne $false
    ) {
        Stop-SosWindows "SOS_WINDOWS_MANIFEST_BINDING_INVALID" "The release manifest does not bind this exact alpha." "Do not continue; copy the complete alpha bundle again."
    }
    $artifactMap = @{}
    foreach ($artifact in @($manifest.artifacts)) {
        if ($null -eq $artifact.filename -or $artifactMap.ContainsKey([string]$artifact.filename)) {
            Stop-SosWindows "SOS_WINDOWS_MANIFEST_BINDING_INVALID" "The release manifest artifact inventory is invalid." "Copy the complete alpha bundle again."
        }
        $artifactMap[[string]$artifact.filename] = [string]$artifact.sha256
    }
    foreach ($name in @($Script:ExpectedFiles | Where-Object { $_ -cne "release-manifest.json" })) {
        if (-not $artifactMap.ContainsKey($name) -or $artifactMap[$name] -cne $checksums[$name]) {
            Stop-SosWindows "SOS_WINDOWS_MANIFEST_BINDING_INVALID" "The release manifest is not bound to '$name'." "Copy the complete alpha bundle again."
        }
    }
    if ($artifactMap.Count -ne ($Script:ExpectedFiles.Count - 1)) {
        Stop-SosWindows "SOS_WINDOWS_MANIFEST_BINDING_INVALID" "The release manifest contains an unexpected artifact." "Copy the complete alpha bundle again."
    }
    return $manifest
}

function Write-Mapping {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$State
    )
    $payload = [ordered]@{
        contract = "sos_windows_wsl2_mapping_v1"
        state = $State
        project_id = $Script:ProjectId
        source_root = $Script:SourceRoot
        source_head = $Script:SourceHead
        source_branch = $Script:SourceBranch
        distro = $Distro
        linux_root = $Script:LinuxRoot
    } | ConvertTo-Json -Compress
    $temporary = "$Path.tmp-$PID"
    [IO.File]::WriteAllText($temporary, $payload, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

if ($env:OS -cne "Windows_NT") {
    Stop-SosWindows "SOS_WINDOWS_HOST_REQUIRED" "This launcher must run in Windows PowerShell." "Use start-sos-alpha directly on Linux."
}
if (-not (Test-SafeToken $Distro)) {
    Stop-SosWindows "SOS_WINDOWS_DISTRO_NAME_INVALID" "The WSL distribution name is not a supported token." "Pass the exact simple name shown by 'wsl.exe --list --quiet'."
}
if ($PrimaryAuthority -and ($PrimaryAuthority.Length -gt 256 -or $PrimaryAuthority -match '[\x00-\x1f]')) {
    Stop-SosWindows "SOS_WINDOWS_AUTHORITY_ID_INVALID" "The primary authority ID is invalid." "Copy one exact ID printed by the SOS compatibility check."
}

$launcher = Get-Item -LiteralPath $PSCommandPath -Force
if (($launcher.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Stop-SosWindows "SOS_WINDOWS_LAUNCHER_REPARSE_POINT" "The Windows launcher must not be run through a reparse point." "Run the checked file directly from the extracted bundle."
}
$bundle = $launcher.Directory.FullName
$manifest = Test-ExactBundle $bundle

$Script:Wsl = (Get-Command "wsl.exe" -ErrorAction SilentlyContinue).Source
if (-not $Script:Wsl) {
    Stop-SosWindows "SOS_WSL2_REQUIRED" "WSL is not installed or is unavailable." "Install WSL2 from Windows Features or Microsoft's documented installer, reboot if requested, then rerun this checked launcher."
}
$listed = Invoke-CheckedProcess -Executable $Script:Wsl -Arguments @("--list", "--quiet") -Capture -AllowFailure
$distroNames = @($listed.Output -split "`n" | ForEach-Object { $_.Trim([char]0).Trim() } | Where-Object { $_ })
if ($listed.ExitCode -ne 0 -or -not ($distroNames -ccontains $Distro)) {
    Stop-SosWindows "SOS_WSL_DISTRO_REQUIRED" "The selected WSL distribution '$Distro' is not installed." "Install a supported x86_64 Ubuntu WSL2 distribution explicitly, complete its first-run user setup, then rerun."
}
$kernel = Invoke-Wsl -Arguments @("cat", "/proc/sys/kernel/osrelease") -Capture -AllowFailure
if ($kernel.ExitCode -ne 0 -or $kernel.Output -notmatch '(?i)microsoft-standard-WSL2') {
    Stop-SosWindows "SOS_WSL2_VERSION_REQUIRED" "The selected distribution is not an admitted WSL2 kernel." "Convert the distribution with 'wsl.exe --set-version <name> 2', then rerun."
}
$architecture = Invoke-Wsl -Arguments @("uname", "-m") -Capture -AllowFailure
if ($architecture.ExitCode -ne 0 -or $architecture.Output -cne "x86_64") {
    Stop-SosWindows "SOS_WSL_ARCHITECTURE_UNSUPPORTED" "The selected WSL2 distribution is not x86_64." "Use an x86_64 WSL2 distribution for this alpha."
}

$gitCommand = (Get-Command "git.exe" -ErrorAction SilentlyContinue).Source
if (-not $gitCommand) {
    Stop-SosWindows "SOS_WINDOWS_GIT_REQUIRED" "Git for Windows was not found." "Install Git for Windows, reopen PowerShell, then rerun."
}
try {
    $requested = (Get-Item -LiteralPath $Project -Force).FullName
}
catch {
    Stop-SosWindows "SOS_WINDOWS_PROJECT_MISSING" "The selected Windows project does not exist." "Pass the path to one existing clean Git repository."
}
$rootProbe = Invoke-CheckedProcess -Executable $gitCommand -Arguments @("-C", $requested, "rev-parse", "--show-toplevel") -Capture -AllowFailure
if ($rootProbe.ExitCode -ne 0 -or -not $rootProbe.Output) {
    Stop-SosWindows "SOS_WINDOWS_GIT_REPOSITORY_REQUIRED" "The selected path is not inside a Git repository." "Pass the path to one existing clean Git repository."
}
$Script:SourceRoot = [IO.Path]::GetFullPath($rootProbe.Output.Trim())
if ($Script:SourceRoot -match '[\x00-\x1f]') {
    Stop-SosWindows "SOS_WINDOWS_PROJECT_PATH_INVALID" "The repository path contains a control character." "Move the repository to a conventional local Windows path and rerun."
}
$sourceStatus = Invoke-CheckedProcess -Executable $gitCommand -Arguments @("-C", $Script:SourceRoot, "status", "--porcelain=v1", "--untracked-files=all") -Capture -AllowFailure
if ($sourceStatus.ExitCode -ne 0 -or $sourceStatus.Output) {
    Stop-SosWindows "SOS_WINDOWS_SOURCE_NOT_CLEAN" "The Windows repository has tracked or untracked changes." "Commit or safely preserve every change before importing the repository into WSL2."
}
$headProbe = Invoke-CheckedProcess -Executable $gitCommand -Arguments @("-C", $Script:SourceRoot, "rev-parse", "HEAD") -Capture -AllowFailure
$branchProbe = Invoke-CheckedProcess -Executable $gitCommand -Arguments @("-C", $Script:SourceRoot, "symbolic-ref", "--quiet", "--short", "HEAD") -Capture -AllowFailure
if ($headProbe.ExitCode -ne 0 -or $headProbe.Output -notmatch '^[0-9a-f]{40}$') {
    Stop-SosWindows "SOS_WINDOWS_SOURCE_HEAD_INVALID" "The repository has no exact commit HEAD." "Create a baseline commit, then rerun."
}
if ($branchProbe.ExitCode -ne 0 -or -not $branchProbe.Output -or $branchProbe.Output.Length -gt 255 -or $branchProbe.Output -match '[\x00-\x1f]') {
    Stop-SosWindows "SOS_WINDOWS_SOURCE_BRANCH_UNSUPPORTED" "The repository is detached or its branch name is outside this alpha contract." "Check out one conventional branch, then rerun."
}
$branchFormat = Invoke-CheckedProcess -Executable $gitCommand -Arguments @("check-ref-format", "--branch", $branchProbe.Output) -Capture -AllowFailure
if ($branchFormat.ExitCode -ne 0) {
    Stop-SosWindows "SOS_WINDOWS_SOURCE_BRANCH_UNSUPPORTED" "The current branch name is not a valid Git branch." "Check out one conventional branch, then rerun."
}
$submoduleProbe = Invoke-CheckedProcess -Executable $gitCommand -Arguments @("-C", $Script:SourceRoot, "ls-files", "--stage") -Capture -AllowFailure
if ($submoduleProbe.ExitCode -ne 0 -or $submoduleProbe.Output -match '(?m)^160000 ') {
    Stop-SosWindows "SOS_WINDOWS_SUBMODULES_UNSUPPORTED" "This alpha does not import repositories containing Git submodules." "Use a repository without submodules or wait for the dedicated import contract."
}
$Script:SourceHead = $headProbe.Output
$Script:SourceBranch = $branchProbe.Output
$Script:ProjectId = Get-ProjectId $Script:SourceRoot $Distro
$leaf = ([IO.Path]::GetFileName($Script:SourceRoot) -replace '[^A-Za-z0-9._-]', '-').Trim('-')
if (-not $leaf) { $leaf = "project" }
$homeProbe = Invoke-Wsl -Arguments @("python3", "-c", "import os; print(os.path.realpath(os.path.expanduser('~')))" ) -Capture -AllowFailure
if ($homeProbe.ExitCode -ne 0 -or $homeProbe.Output -notmatch '^/[^\x00-\x1f]+$' -or $homeProbe.Output -match '^/mnt/') {
    Stop-SosWindows "SOS_WSL_PYTHON_OR_HOME_INVALID" "WSL Python 3 or a native Linux home could not be established." "Install Python 3.11/3.12 inside the selected WSL2 distribution and complete its user setup."
}
$pythonVersion = Invoke-Wsl -Arguments @("python3", "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')") -Capture -AllowFailure
if ($pythonVersion.ExitCode -ne 0 -or @("3.11", "3.12") -cnotcontains $pythonVersion.Output) {
    Stop-SosWindows "SOS_WSL_PYTHON_UNSUPPORTED" "The selected WSL2 distribution does not provide Python 3.11 or 3.12." "Install Python 3.11 or 3.12 inside this WSL2 distribution, then rerun."
}
foreach ($prerequisite in @("git", "uv", "codex")) {
    $probe = Invoke-Wsl -Arguments @($prerequisite, "--version") -Capture -AllowFailure
    if ($probe.ExitCode -ne 0) {
        Stop-SosWindows "SOS_WSL_PREREQUISITE_MISSING" "Required command '$prerequisite' was not found inside '$Distro'." "Install $prerequisite for the same WSL user, then rerun."
    }
}
$Script:LinuxRoot = "$($homeProbe.Output.TrimEnd('/'))/.local/share/sos/workspaces/$leaf-$($Script:ProjectId)"
if ($Script:LinuxRoot -match '^/mnt/') {
    Stop-SosWindows "SOS_WINDOWS_CANONICAL_PATH_UNSAFE" "The computed SOS workspace is Windows-backed." "Use a WSL distribution with a native Linux home filesystem."
}

$localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if (-not $localData) {
    Stop-SosWindows "SOS_WINDOWS_LOCAL_STATE_UNAVAILABLE" "The Windows local application-data directory is unavailable." "Use a normal non-roaming Windows user profile and rerun."
}
$mappingDirectory = Join-Path $localData "SigmaOperatorStack\projects"
$mappingPath = Join-Path $mappingDirectory "$($Script:ProjectId).json"
$existingState = $null
if (Test-Path -LiteralPath $mappingPath -PathType Leaf) {
    try {
        $existingState = Get-Content -LiteralPath $mappingPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Stop-SosWindows "SOS_WINDOWS_MAPPING_INVALID" "The stable project mapping is unreadable." "Preserve the mapping file and request bounded recovery; do not create another workspace."
    }
    if (
        $existingState.contract -cne "sos_windows_wsl2_mapping_v1" -or
        $existingState.project_id -cne $Script:ProjectId -or
        $existingState.source_root -cne $Script:SourceRoot -or
        $existingState.source_head -cne $Script:SourceHead -or
        $existingState.source_branch -cne $Script:SourceBranch -or
        $existingState.distro -cne $Distro -or
        $existingState.linux_root -cne $Script:LinuxRoot -or
        @("importing", "imported", "ready") -cnotcontains $existingState.state
    ) {
        Stop-SosWindows "SOS_WINDOWS_MAPPING_DRIFT" "The stable project mapping does not match the current request." "Preserve both workspaces and request bounded mapping recovery."
    }
}

$targetProbe = Invoke-Wsl -Arguments @("test", "-e", $Script:LinuxRoot) -Capture -AllowFailure
$targetExists = $targetProbe.ExitCode -eq 0
if ($null -eq $existingState -and $targetExists) {
    Stop-SosWindows "SOS_WINDOWS_TARGET_COLLISION" "The native WSL target already exists without a matching stable mapping." "Choose a different Windows repository or preserve and inspect the existing Linux workspace."
}
if ($null -ne $existingState -and -not $targetExists) {
    Stop-SosWindows "SOS_WINDOWS_MAPPING_TARGET_MISSING" "The stable mapping points to a missing Linux workspace." "Preserve the mapping and request bounded recovery; do not silently re-import."
}
if ($targetExists) {
    $targetHead = Invoke-Wsl -Arguments @("git", "-C", $Script:LinuxRoot, "rev-parse", "HEAD") -Capture -AllowFailure
    if ($targetHead.ExitCode -ne 0) {
        Stop-SosWindows "SOS_WINDOWS_TARGET_REPOSITORY_INVALID" "The mapped Linux workspace is not a readable Git repository." "Preserve it and request bounded recovery; do not overwrite it from Windows."
    }
    if ($existingState.state -cne "ready" -and $targetHead.Output -cne $Script:SourceHead) {
        Stop-SosWindows "SOS_WINDOWS_TARGET_HEAD_DRIFT" "The mapped Linux workspace no longer has the imported source HEAD." "Open the mapped WSL workspace directly; do not overwrite it from Windows."
    }
}

$plan = [ordered]@{
    contract = "sos_windows_wsl2_plan_v1"
    status = "ready"
    release = [string]$manifest.version
    candidate = [string]$manifest.candidate
    source = [ordered]@{ root = $Script:SourceRoot; head = $Script:SourceHead; branch = $Script:SourceBranch }
    substrate = [ordered]@{ distro = $Distro; kernel = $kernel.Output; architecture = $architecture.Output }
    target = $Script:LinuxRoot
    mapping = $mappingPath
    import_required = -not $targetExists
    qualification_runs = $false
    opens_codex = -not $NoOpenCodex
}
$planJson = $plan | ConvertTo-Json -Depth 5
Write-Host $planJson
if ($PlanOnly) {
    exit 0
}
$confirmation = Read-Host "Type INSTALL to import/connect this exact plan"
if ($confirmation -cne "INSTALL") {
    Stop-SosWindows "SOS_WINDOWS_CONFIRMATION_REQUIRED" "The exact Windows/WSL2 plan was not confirmed." "Rerun when you are ready and type INSTALL exactly once."
}

New-Item -ItemType Directory -Path $mappingDirectory -Force | Out-Null
if (-not $targetExists) {
    Write-Mapping $mappingPath "importing"
    $temporaryBundle = Join-Path ([IO.Path]::GetTempPath()) "sos-$($Script:ProjectId)-$PID.bundle"
    try {
        $bundleResult = Invoke-CheckedProcess -Executable $gitCommand -Arguments @("-C", $Script:SourceRoot, "bundle", "create", $temporaryBundle, "--all") -AllowFailure
        if ($bundleResult -ne 0) {
            Stop-SosWindows "SOS_WINDOWS_GIT_BUNDLE_FAILED" "Git could not create the bounded repository transfer." "Preserve the source and mapping, correct the Git error, then rerun."
        }
        $bundleVerify = Invoke-CheckedProcess -Executable $gitCommand -Arguments @("bundle", "verify", $temporaryBundle) -Capture -AllowFailure
        if ($bundleVerify.ExitCode -ne 0) {
            Stop-SosWindows "SOS_WINDOWS_GIT_BUNDLE_INVALID" "The bounded repository transfer failed verification." "Preserve the source and mapping, then rerun after correcting Git."
        }
        $wslBundle = Invoke-Wsl -Arguments @("wslpath", "-u", $temporaryBundle) -Capture -AllowFailure
        if ($wslBundle.ExitCode -ne 0 -or $wslBundle.Output -notmatch '^/mnt/') {
            Stop-SosWindows "SOS_WINDOWS_PATH_PROJECTION_FAILED" "WSL could not project the temporary transfer path." "Check WSL interop and rerun."
        }
        $parent = $Script:LinuxRoot.Substring(0, $Script:LinuxRoot.LastIndexOf('/'))
        $staging = "$($Script:LinuxRoot).staging-$($Script:ProjectId)"
        if ((Invoke-Wsl -Arguments @("test", "-e", $staging) -Capture -AllowFailure).ExitCode -eq 0) {
            Stop-SosWindows "SOS_WINDOWS_IMPORT_RECOVERY_REQUIRED" "A prior bounded import staging directory still exists." "Preserve it and request bounded recovery; this launcher will not delete it automatically."
        }
        Invoke-Wsl -Arguments @("mkdir", "-p", $parent) | Out-Null
        Invoke-Wsl -Arguments @("git", "clone", "--no-checkout", $wslBundle.Output, $staging) | Out-Null
        Invoke-Wsl -Arguments @("git", "-C", $staging, "checkout", "-B", $Script:SourceBranch, $Script:SourceHead) | Out-Null
        Invoke-Wsl -Arguments @("git", "-C", $staging, "remote", "remove", "origin") -AllowFailure | Out-Null
        $importHead = Invoke-Wsl -Arguments @("git", "-C", $staging, "rev-parse", "HEAD") -Capture -AllowFailure
        $importStatus = Invoke-Wsl -Arguments @("git", "-C", $staging, "status", "--porcelain=v1", "--untracked-files=all") -Capture -AllowFailure
        if ($importHead.ExitCode -ne 0 -or $importHead.Output -cne $Script:SourceHead -or $importStatus.ExitCode -ne 0 -or $importStatus.Output) {
            Stop-SosWindows "SOS_WINDOWS_IMPORT_VERIFICATION_FAILED" "The native WSL import did not preserve the exact clean source." "Preserve the staging directory and request bounded recovery."
        }
        Invoke-Wsl -Arguments @("mv", $staging, $Script:LinuxRoot) | Out-Null
        Write-Mapping $mappingPath "imported"
    }
    finally {
        if (Test-Path -LiteralPath $temporaryBundle -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryBundle -Force
        }
    }
}

$wslBundleRoot = Invoke-Wsl -Arguments @("wslpath", "-u", $bundle) -Capture -AllowFailure
if ($wslBundleRoot.ExitCode -ne 0 -or $wslBundleRoot.Output -notmatch '^/mnt/') {
    Stop-SosWindows "SOS_WINDOWS_BUNDLE_PROJECTION_FAILED" "WSL could not access the checked alpha bundle." "Move the extracted bundle to a conventional local Windows folder and rerun."
}
$linuxLauncher = "$($wslBundleRoot.Output.TrimEnd('/'))/start-sos-alpha"
$linuxArguments = @("python3", $linuxLauncher)
if ($PrimaryAuthority) {
    $linuxArguments += @("--primary-authority", $PrimaryAuthority)
}
$linuxArguments += $Script:LinuxRoot
$setupWslArguments = @("-d", $Distro, "--exec") + $linuxArguments
& $Script:Wsl @setupWslArguments
$setupResult = $LASTEXITCODE
if ($setupResult -ne 0) {
    Stop-SosWindows "SOS_WINDOWS_LINUX_SETUP_BLOCKED" "The checked Linux SOS setup did not complete." "Read the typed Linux result above, correct it, and rerun this launcher; the stable mapping will be reused."
}
Write-Mapping $mappingPath "ready"

[ordered]@{
    contract = $Script:Contract
    status = "success"
    reason = "SOS_WINDOWS_WSL2_READY"
    distro = $Distro
    linux_root = $Script:LinuxRoot
    mapping_state = "ready"
    qualification_state = "not_verified"
    next_action = "Run sos qualify in the mapped WSL workspace when you are ready."
} | ConvertTo-Json -Compress | Write-Host

if (-not $NoOpenCodex) {
    Write-Host "Opening Codex in the same native WSL2 workspace."
    & $Script:Wsl -d $Distro --exec codex -C $Script:LinuxRoot
    $codexResult = $LASTEXITCODE
    if ($codexResult -ne 0) {
        Stop-SosWindows "SOS_WINDOWS_CODEX_OPEN_FAILED" "Codex did not open in the mapped WSL workspace." "Inside '$Distro', run: codex -C '$($Script:LinuxRoot)'."
    }
}
