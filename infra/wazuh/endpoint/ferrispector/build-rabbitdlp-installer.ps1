[CmdletBinding()]
param(
  [ValidateSet('x64', 'arm64')]
  [string] $Architecture = 'x64',

  [ValidatePattern('^\d+\.\d+\.\d+$')]
  [string] $AppVersion = '1.1.0',

  [string] $OutputDirectory,

  [string] $InnoCompiler
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $root '..\..\..\..')).Path
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo 'dist\rabbitdlp' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

if (-not $InnoCompiler) {
  $command = Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue
  if ($command) { $InnoCompiler = $command.Source }
}
if (-not $InnoCompiler) {
  $knownCompilers = @(
    'C:\Program Files\Inno Setup 7\ISCC.exe',
    'C:\Program Files (x86)\Inno Setup 7\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe',
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
  )
  $InnoCompiler = $knownCompilers | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (-not $InnoCompiler -or -not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
  throw 'Inno Setup 6.4 or newer is required. Install it from https://jrsoftware.org/isdl.php or pass -InnoCompiler C:\path\ISCC.exe.'
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('rabbitdlp-build-' + [guid]::NewGuid().ToString('N'))
$payloadPath = Join-Path $temporaryRoot ("RabbitDLP-Windows-$Architecture-payload.zip")
$packageBuilder = Join-Path $root 'build-windows-package.ps1'
$setupSource = Join-Path $root 'rabbitdlp-setup.iss'
$setupName = "RabbitDLP-Setup-Windows-$Architecture-$AppVersion.exe"
$setupPath = Join-Path $OutputDirectory $setupName
$compileOutputDirectory = Join-Path $temporaryRoot 'compiled'
$compiledSetupPath = Join-Path $compileOutputDirectory $setupName

try {
  New-Item -ItemType Directory -Path $temporaryRoot, $compileOutputDirectory -Force | Out-Null
  & $packageBuilder -Architecture $Architecture -OutputPath $payloadPath
  $payloadSha256 = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $payloadShaPath = $payloadPath + '.sha256'
  if (Test-Path -LiteralPath $payloadShaPath) { Remove-Item -LiteralPath $payloadShaPath -Force }

  Push-Location $root
  try {
    & $InnoCompiler `
      "/DAppVersion=$AppVersion" `
      "/DArchitecture=$Architecture" `
      "/DPayloadPath=$payloadPath" `
      "/DPayloadSha256=$payloadSha256" `
      "/DOutputDirectory=$compileOutputDirectory" `
      $setupSource
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed with exit code $LASTEXITCODE." }
  }
  finally { Pop-Location }

  if (-not (Test-Path -LiteralPath $compiledSetupPath -PathType Leaf)) { throw 'The RabbitDLP installer was not produced.' }
  Move-Item -LiteralPath $compiledSetupPath -Destination $setupPath -Force
  $setupSha256 = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
  Set-Content -LiteralPath ($setupPath + '.sha256') -Value ($setupSha256 + '  ' + [IO.Path]::GetFileName($setupPath)) -Encoding ascii
  Write-Output "Created $setupPath (RabbitDLP $AppVersion, $Architecture, SHA-256: $setupSha256)."
}
finally {
  if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
