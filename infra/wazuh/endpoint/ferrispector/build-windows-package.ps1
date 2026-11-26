[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('x64', 'arm64')]
  [string] $Architecture,

  [string] $RulesPath,

  [ValidatePattern('^\d+\.\d+\.\d+$')]
  [string] $PolicyVersion = '1.0.0',

  [Parameter(Mandatory = $true)]
  [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Version = '1.24.0'
$Assets = @{
  x64 = @{
    Name = "yara-x-v$Version-x86_64-pc-windows-msvc.zip"
    Sha256 = '8b68b49e051b2d2787a74df5588fcf65d41bd21b27689061fd16a80516cb9336'
  }
  arm64 = @{
    Name = "yara-x-v$Version-aarch64-pc-windows-msvc.zip"
    Sha256 = 'aa1a8986ac7b06f33a8f0941ca1482acf31eb1b158c7f9a517ec940fffa84311'
  }
}

$asset = $Assets[$Architecture]
$releaseUrl = "https://github.com/VirusTotal/yara-x/releases/download/v$Version/$($asset.Name)"
$nativeArchitecture = (Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1 -ExpandProperty Architecture)
$compilerArchitecture = switch ($nativeArchitecture) {
  9 { 'x64' }
  12 { 'arm64' }
  default { throw "Unsupported Windows build-host architecture code '$nativeArchitecture'; a native x64 or ARM64 Windows host is required." }
}
$compilerAsset = $Assets[$compilerArchitecture]
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("b89-ferrispector-" + [guid]::NewGuid().ToString('N'))
$archivePath = Join-Path $temporaryRoot $asset.Name
$compilerArchivePath = Join-Path $temporaryRoot ('compiler-' + $compilerAsset.Name)
$extractPath = Join-Path $temporaryRoot 'extract'
$compilerExtractPath = Join-Path $temporaryRoot 'compiler-extract'
$stagePath = Join-Path $temporaryRoot 'package'
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)

if (-not $RulesPath) { $RulesPath = Join-Path $PSScriptRoot 'policy\starter-credentials.yar' }
if (-not (Test-Path -LiteralPath $RulesPath -PathType Leaf)) { throw 'RulesPath must identify an existing .yar or .yara policy file.' }

  if ([IO.Path]::GetExtension($RulesPath) -notin @('.yar', '.yara')) { throw 'RulesPath must be one approved .yar or .yara policy file.' }
if ((Get-Item -LiteralPath $RulesPath).Length -eq 0) { throw 'RulesPath is empty; a policy file is required.' }
if ([IO.Path]::GetExtension($outputFullPath) -ne '.zip') { throw 'OutputPath must end in .zip.' }

try {
  New-Item -ItemType Directory -Path $temporaryRoot, $extractPath, $compilerExtractPath, $stagePath -Force | Out-Null
  Invoke-WebRequest -Uri $releaseUrl -OutFile $archivePath
  $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualHash -ne $asset.Sha256) {
    throw "YARA-X archive SHA-256 mismatch: expected $($asset.Sha256), got $actualHash."
  }

  Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force
  $yr = Get-ChildItem -LiteralPath $extractPath -Filter 'yr.exe' -File -Recurse | Select-Object -First 1
  if (-not $yr) { throw 'The verified YARA-X archive did not contain yr.exe.' }

  $compilerYr = $yr.FullName
  if ($compilerArchitecture -ne $Architecture) {
    $compilerUrl = "https://github.com/VirusTotal/yara-x/releases/download/v$Version/$($compilerAsset.Name)"
    Invoke-WebRequest -Uri $compilerUrl -OutFile $compilerArchivePath
    $compilerArchiveHash = (Get-FileHash -LiteralPath $compilerArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($compilerArchiveHash -ne $compilerAsset.Sha256) {
      throw "Native YARA-X compiler archive SHA-256 mismatch: expected $($compilerAsset.Sha256), got $compilerArchiveHash."
    }
    Expand-Archive -LiteralPath $compilerArchivePath -DestinationPath $compilerExtractPath -Force
    $hostYr = Get-ChildItem -LiteralPath $compilerExtractPath -Filter 'yr.exe' -File -Recurse | Select-Object -First 1
    if (-not $hostYr) { throw 'The verified native YARA-X compiler archive did not contain yr.exe.' }
    $compilerYr = $hostYr.FullName
  }

  $binPath = Join-Path $stagePath 'bin'
  $policyPath = Join-Path $stagePath 'policy'
  New-Item -ItemType Directory -Path $binPath, $policyPath -Force | Out-Null
  Copy-Item -LiteralPath $yr.FullName -Destination (Join-Path $binPath 'yr.exe')
  $sourcePolicyPath = Join-Path $policyPath 'approved-dlp-rules.yar'
  $compiledPolicyPath = Join-Path $policyPath 'dlp-rules.yarc'
  Copy-Item -LiteralPath $RulesPath -Destination $sourcePolicyPath
  $fingerprintSourcePath = Join-Path $policyPath 'fingerprints.sha256'
  $fingerprintCatalogPath = Join-Path $PSScriptRoot 'policy\fingerprints.sha256'
  if (-not (Test-Path -LiteralPath $fingerprintCatalogPath -PathType Leaf)) {
    throw 'The approved fingerprint catalog file is missing.'
  }
  foreach ($line in (Get-Content -LiteralPath $fingerprintCatalogPath)) {
    $value = $line.Trim()
    if ($value -and -not $value.StartsWith('#') -and $value -notmatch '^[0-9a-fA-F]{64}$') {
      throw 'Each fingerprint must be one SHA-256 hash (64 hexadecimal characters) per line.'
    }
  }
  Copy-Item -LiteralPath $fingerprintCatalogPath -Destination $fingerprintSourcePath
  $policySourceSha256 = (Get-FileHash -LiteralPath $sourcePolicyPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $fingerprintCatalogSha256 = (Get-FileHash -LiteralPath $fingerprintSourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
  $priorErrorPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $compilerOutputPath = Join-Path $temporaryRoot 'yara-x-compile.stdout.txt'
  $compilerErrorPath = Join-Path $temporaryRoot 'yara-x-compile.stderr.txt'
  try {
    $compileProcess = Start-Process -FilePath $compilerYr `
      -ArgumentList @('compile', ('"' + $sourcePolicyPath + '"'), '--output', ('"' + $compiledPolicyPath + '"')) `
      -WindowStyle Hidden -Wait -PassThru `
      -RedirectStandardOutput $compilerOutputPath -RedirectStandardError $compilerErrorPath
    $compileExitCode = $compileProcess.ExitCode
    $compileOutput = @()
    if (Test-Path -LiteralPath $compilerOutputPath) { $compileOutput += Get-Content -LiteralPath $compilerOutputPath }
    if (Test-Path -LiteralPath $compilerErrorPath) { $compileOutput += Get-Content -LiteralPath $compilerErrorPath }
  }
  finally { $ErrorActionPreference = $priorErrorPreference }
  if ($compileExitCode -ne 0 -or -not (Test-Path -LiteralPath $compiledPolicyPath -PathType Leaf)) {
    throw "YARA-X rejected the supplied DLP policy: $($compileOutput -join ' ')"
  }
  Remove-Item -LiteralPath $sourcePolicyPath -Force
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ferrispector.ps1') -Destination $stagePath
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install-windows-endpoint.ps1') -Destination $stagePath
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'rabbitdlp-device-control.ps1') -Destination $stagePath
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'rabbitdlp-quarantine.ps1') -Destination $stagePath
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'restore-quarantined-file.ps1') -Destination $stagePath
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'THIRD-PARTY-NOTICES.txt') -Destination $stagePath

  $manifest = [ordered]@{
    product = 'RabbitDLP'
    agent = 'Ferrispector'
    engine = 'YARA-X CLI'
    engineVersion = $Version
    architecture = $Architecture
    policyName = [IO.Path]::GetFileNameWithoutExtension($RulesPath)
    policyVersion = $PolicyVersion
    policySourceSha256 = $policySourceSha256
    fingerprintCatalogSha256 = $fingerprintCatalogSha256
    sourceUrl = $releaseUrl
    sourceArchiveSha256 = $asset.Sha256
    engineBinarySha256 = (Get-FileHash -LiteralPath (Join-Path $binPath 'yr.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    rulesSha256 = (Get-FileHash -LiteralPath $compiledPolicyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    licenseNotice = 'THIRD-PARTY-NOTICES.txt'
    installMode = 'detection, exact-fingerprint quarantine and optional Defender device control; monitored roots are operator supplied'
  }
  $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $stagePath 'manifest.json') -Encoding utf8

  $parent = Split-Path -Parent $outputFullPath
  if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  if (Test-Path -LiteralPath $outputFullPath) { throw "Output already exists; choose a new package path: $outputFullPath" }
  Compress-Archive -Path (Join-Path $stagePath '*') -DestinationPath $outputFullPath -CompressionLevel Optimal
  $packageSha256 = (Get-FileHash -LiteralPath $outputFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
  Set-Content -LiteralPath ($outputFullPath + '.sha256') -Value ($packageSha256 + '  ' + [IO.Path]::GetFileName($outputFullPath)) -Encoding ascii
  Write-Output "Created $outputFullPath (YARA-X v$Version, $Architecture, verified SHA-256: $packageSha256)."
}
finally {
  if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
