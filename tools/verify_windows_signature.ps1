param(
    [Parameter(Mandatory = $true)][string]$File,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Candidate,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Tree,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$UnsignedSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedPublisher,
    [Parameter(Mandatory = $true)][string]$SigningAccount,
    [Parameter(Mandatory = $true)][string]$CertificateProfile,
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $File
if ($item.PSIsContainer -or $item.LinkType) { throw 'signed input is not one regular file' }
$signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Windows trust verification failed: $($signature.Status)"
}
if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -cne $ExpectedPublisher) {
    throw 'signing publisher mismatch'
}
if ($null -eq $signature.TimeStamperCertificate) { throw 'RFC3161 timestamp is absent or invalid' }
$signedSha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($signedSha256 -eq $UnsignedSha256) { throw 'signing transformation did not change the artifact' }

$record = [ordered]@{
    candidate = $Candidate
    certificate_profile = $CertificateProfile
    contract = 'sos_windows_signing_evidence_v1'
    file_digest_algorithm = 'SHA256'
    publisher = $signature.SignerCertificate.Subject
    signed_sha256 = $signedSha256
    signing_account = $SigningAccount
    status = 'passed'
    timestamp_digest_algorithm = 'SHA256'
    timestamp_present = $true
    tree = $Tree
    unsigned_sha256 = $UnsignedSha256
}
$json = $record | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText($Output, $json + "`n", [System.Text.UTF8Encoding]::new($false))
Write-Output $json

