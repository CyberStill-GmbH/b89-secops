[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string] $FerrispectorPackage,

  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9a-fA-F]{64}$')]
  [string] $ExpectedPackageSha256,

  [Parameter(Mandatory = $true)]
  [string] $WazuhManager,

  [ValidatePattern('^[A-Za-z0-9_.,-]{1,255}$')]
  [string] $WazuhAgentGroup = 'windows-workstations',

  [string] $WazuhAgentName = $env:COMPUTERNAME,

  [string[]] $WatchRoot,

  [string] $DlpControlPlaneUrl,

  [System.Security.SecureString] $RegistrationPassword
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell session.'
  }
}

function Set-PrivateAcl {
  param([Parameter(Mandatory = $true)][string] $Path)
  $item = Get-Item -LiteralPath $Path -Force
  $systemAcl = if ($item.PSIsContainer) { 'SYSTEM:(OI)(CI)F' } else { 'SYSTEM:F' }
  $adminAcl = if ($item.PSIsContainer) { 'BUILTIN\Administrators:(OI)(CI)F' } else { 'BUILTIN\Administrators:F' }
  & icacls.exe $Path /inheritance:r /grant:r $systemAcl $adminAcl | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not restrict ACLs on $Path." }
}

function Get-WindowsArchitecture {
  $nativeArchitecture = (Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1 -ExpandProperty Architecture)
  if ($nativeArchitecture -eq 12) { return 'arm64' }
  if ($nativeArchitecture -eq 9) { return 'x64' }
  throw "Unsupported Windows architecture code '$nativeArchitecture'; only x64 and ARM64 are packaged."
}

function Add-WazuhFerrispectorLocalfile {
  $agentConfig = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
  if (-not (Test-Path -LiteralPath $agentConfig -PathType Leaf)) { throw 'Wazuh ossec.conf is missing after enrollment.' }
  $eventsLocation = Join-Path $env:ProgramData 'B89\Ferrispector\events.jsonl'
  $eventsLocation = [Security.SecurityElement]::Escape([IO.Path]::GetFullPath($eventsLocation))
  $current = Get-Content -LiteralPath $agentConfig -Raw
  $begin = '<!-- B89:FERRISPECTOR:BEGIN -->'
  $end = '<!-- B89:FERRISPECTOR:END -->'
  $block = @'
  <!-- B89:FERRISPECTOR:BEGIN -->
  <localfile>
    <location>__B89_FERRISPECTOR_EVENT_PATH__</location>
    <log_format>json</log_format>
  </localfile>
  <!-- B89:FERRISPECTOR:END -->
'@
  $block = $block.Replace('__B89_FERRISPECTOR_EVENT_PATH__', $eventsLocation)
  $pattern = '(?s)' + [regex]::Escape($begin) + '.*?' + [regex]::Escape($end)
  $existingBlock = [regex]::Match($current, $pattern)
  if ($existingBlock.Success) {
    $updated = $current.Remove($existingBlock.Index, $existingBlock.Length).Insert($existingBlock.Index, $block.TrimEnd())
  }
  elseif ($current -match '</ossec_config>') {
    $updated = $current.Replace('</ossec_config>', ($block + "`r`n</ossec_config>"))
  }
  else { throw 'Wazuh ossec.conf has no closing </ossec_config> element.' }
  if ($updated -cne $current) {
    [IO.File]::WriteAllText($agentConfig, $updated, [Text.UTF8Encoding]::new($false))
    return $true
  }
  return $false
}

function Install-WazuhAgentIfMissing {
  param([Parameter(Mandatory = $true)][string] $AgentManager)

  $agentService = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
  $agentConfig = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
  if ($agentService) {
    if (-not (Test-Path -LiteralPath $agentConfig)) { throw 'WazuhSvc exists but its ossec.conf is missing.' }
    $configText = Get-Content -LiteralPath $agentConfig -Raw
    if ($configText -notmatch ('<address>' + [regex]::Escape($AgentManager) + '</address>')) {
      throw "Wazuh agent is already installed and points to a different manager; no settings were changed."
    }
    Write-Output "Reusing Wazuh agent for $AgentManager."
    return
  }

  if (-not $RegistrationPassword) {
    $script:RegistrationPassword = Read-Host 'Wazuh enrollment password' -AsSecureString
  }
  if (-not $script:RegistrationPassword -or $script:RegistrationPassword.Length -eq 0) {
    throw 'A Wazuh enrollment password is required when installing a new Wazuh agent.'
  }

  $version = '4.14.10'
  $msiPath = Join-Path ([IO.Path]::GetTempPath()) ("wazuh-agent-$version-1-$([guid]::NewGuid().ToString('N')).msi")
  $msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$version-1.msi"
  try {
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath
    $signature = Get-AuthenticodeSignature -LiteralPath $msiPath
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
      throw "Wazuh MSI signature is not valid ($($signature.Status))."
    }
    $publisher = $signature.SignerCertificate.GetNameInfo(
      [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
      $false
    )
    if ($publisher -cne 'Wazuh, Inc') {
      throw "Wazuh MSI signer is '$publisher'; expected 'Wazuh, Inc'."
    }
    $arguments = @(
      '/i', ('"' + $msiPath + '"'), '/qn', '/norestart',
      ('WAZUH_MANAGER="' + $AgentManager + '"'),
      ('WAZUH_AGENT_GROUP="' + $WazuhAgentGroup + '"'),
      ('WAZUH_AGENT_NAME="' + $WazuhAgentName + '"')
    ) -join ' '
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw "Wazuh MSI installation failed with exit code $($process.ExitCode)." }
  }
  finally {
    if (Test-Path -LiteralPath $msiPath) { Remove-Item -LiteralPath $msiPath -Force }
  }

  $agentService = Get-Service -Name 'WazuhSvc' -ErrorAction Stop
  if ($agentService.Status -ne 'Stopped') { Stop-Service -Name 'WazuhSvc' -Force }
  $agentHome = 'C:\Program Files (x86)\ossec-agent'
  $passwordPath = Join-Path $agentHome 'authd.pass'
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:RegistrationPassword)
  try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [IO.File]::WriteAllText($passwordPath, $plainPassword, [Text.Encoding]::ASCII)
    Set-PrivateAcl -Path $passwordPath
  }
  finally {
    if ($plainPassword) { $plainPassword = $null }
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }
  Set-Service -Name 'WazuhSvc' -StartupType Automatic
  Start-Service -Name 'WazuhSvc'
  Write-Output "Installed Wazuh agent $version for $AgentManager in group $WazuhAgentGroup."
}

Assert-Administrator
if ($WazuhManager -notmatch '^[A-Za-z0-9.-]{1,253}$') { throw 'WazuhManager must be a host name or IPv4 address.' }
if ($WazuhAgentName -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw 'WazuhAgentName contains unsupported characters.' }
if (-not $WatchRoot -or $WatchRoot.Count -eq 0) { throw 'Supply at least one explicitly approved local WatchRoot; the installer chooses no directories.' }
foreach ($root in $WatchRoot) {
  if ($root.StartsWith('\\') -or -not [IO.Path]::IsPathRooted($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "WatchRoot must be an existing local directory: $root"
  }
  if (((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "WatchRoot cannot be a reparse point: $root"
  }
}

$packagePath = [IO.Path]::GetFullPath($FerrispectorPackage)
if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) { throw 'Ferrispector package zip was not found.' }
$packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($packageHash -ne $ExpectedPackageSha256.ToLowerInvariant()) { throw 'Ferrispector package SHA-256 does not match the independently supplied expected hash.' }
$architecture = Get-WindowsArchitecture
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("b89-ferrispector-install-" + [guid]::NewGuid().ToString('N'))
try {
  New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
  Expand-Archive -LiteralPath $packagePath -DestinationPath $temporaryRoot
  $manifestPath = Join-Path $temporaryRoot 'manifest.json'
  if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Ferrispector package is missing manifest.json.' }
  $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
  if ($manifest.product -ne 'B89 Ferrispector' -or $manifest.engine -ne 'YARA-X CLI' -or
      $manifest.engineVersion -ne '1.24.0' -or $manifest.architecture -ne $architecture) {
    throw 'Ferrispector package identity, pinned YARA-X version, or architecture does not match this endpoint.'
  }
  if ($manifest.installMode -ne 'detection-only; rule pack and monitored roots are operator supplied') {
    throw 'Ferrispector package install mode is not recognized.'
  }
  $sourceEngine = Join-Path $temporaryRoot 'bin\yr.exe'
  $sourceRules = Join-Path $temporaryRoot 'policy\dlp-rules.yarc'
  $sourceFingerprints = Join-Path $temporaryRoot 'policy\fingerprints.sha256'
  if (-not (Test-Path -LiteralPath $sourceEngine -PathType Leaf) -or -not (Test-Path -LiteralPath $sourceRules -PathType Leaf) -or
      -not (Test-Path -LiteralPath $sourceFingerprints -PathType Leaf)) {
    throw 'Ferrispector package must contain YARA-X, its DLP rules and a SHA-256 fingerprint catalog.'
  }
  $engineHash = (Get-FileHash -LiteralPath $sourceEngine -Algorithm SHA256).Hash.ToLowerInvariant()
  $rulesHash = (Get-FileHash -LiteralPath $sourceRules -Algorithm SHA256).Hash.ToLowerInvariant()
  $fingerprintHash = (Get-FileHash -LiteralPath $sourceFingerprints -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($engineHash -ne $manifest.engineBinarySha256.ToLowerInvariant() -or $rulesHash -ne $manifest.rulesSha256.ToLowerInvariant() -or
      $fingerprintHash -ne $manifest.fingerprintCatalogSha256.ToLowerInvariant()) {
    throw 'Ferrispector package file hashes do not match the manifest.'
  }
  foreach ($line in (Get-Content -LiteralPath $sourceFingerprints)) {
    $value = $line.Trim()
    if ($value -and -not $value.StartsWith('#') -and $value -notmatch '^[0-9a-fA-F]{64}$') {
      throw 'Ferrispector fingerprint catalog contains an invalid entry.'
    }
  }
  $notices = Join-Path $temporaryRoot 'THIRD-PARTY-NOTICES.txt'
  if (-not (Test-Path -LiteralPath $notices -PathType Leaf) -or
      -not (Select-String -LiteralPath $notices -SimpleMatch 'YARA-X Authors' -Quiet)) {
    throw 'Ferrispector package is missing the upstream YARA-X license notice.'
  }
  Get-ChildItem -LiteralPath $temporaryRoot -Filter '*.ps1' -File -Recurse | Unblock-File

  # All package/configuration checks complete before changing the endpoint.
  Install-WazuhAgentIfMissing -AgentManager $WazuhManager

  # Bind installation identity to the entire verified package so a wrapper,
  # installer, notice, or policy change always creates a distinct release.
  $releaseId = "yara-x-$($manifest.engineVersion)-$architecture-$($packageHash.Substring(0, 16))"
  $installRoot = Join-Path $env:ProgramFiles 'B89\Ferrispector'
  $releasesRoot = Join-Path $installRoot 'releases'
  $releasePath = Join-Path $releasesRoot $releaseId
  New-Item -ItemType Directory -Path $releasesRoot -Force | Out-Null
  if (-not (Test-Path -LiteralPath (Join-Path $releasePath 'manifest.json'))) {
    $stagePath = Join-Path $releasesRoot ($releaseId + '.staging')
    if (Test-Path -LiteralPath $stagePath) { Remove-Item -LiteralPath $stagePath -Recurse -Force }
    New-Item -ItemType Directory -Path $stagePath -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $temporaryRoot 'bin') -Destination $stagePath -Recurse
    Copy-Item -LiteralPath (Join-Path $temporaryRoot 'policy') -Destination $stagePath -Recurse
    Copy-Item -LiteralPath (Join-Path $temporaryRoot 'ferrispector.ps1') -Destination $stagePath
    Copy-Item -LiteralPath $notices -Destination $stagePath
    Copy-Item -LiteralPath $manifestPath -Destination $stagePath
    Move-Item -LiteralPath $stagePath -Destination $releasePath
  }

  $dataRoot = Join-Path $env:ProgramData 'B89\Ferrispector'
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  Set-PrivateAcl -Path $dataRoot
  $eventsPath = Join-Path $dataRoot 'events.jsonl'
  if (-not (Test-Path -LiteralPath $eventsPath)) { [IO.File]::WriteAllText($eventsPath, '', [Text.UTF8Encoding]::new($false)) }
  $configPath = Join-Path $dataRoot 'config.json'
  $config = [ordered]@{
    schema_version = 1
    rules_path = (Join-Path $releasePath 'policy\dlp-rules.yarc')
    fingerprints_path = (Join-Path $releasePath 'policy\fingerprints.sha256')
    events_path = $eventsPath
    watch_roots = @($WatchRoot | ForEach-Object { [IO.Path]::GetFullPath($_) })
    include_subdirectories = $true
    reconcile_interval_minutes = 60
  }
  if ($DlpControlPlaneUrl) {
    $controlPlane = [Uri]$DlpControlPlaneUrl
    if ($controlPlane.Scheme -ne 'https' -or $controlPlane.UserInfo -or $controlPlane.Query -or $controlPlane.Fragment) {
      throw 'DlpControlPlaneUrl must be an HTTPS origin or base path without credentials, query or fragment.'
    }
    $secureToken = Read-Host 'Token de inscripción de DLP (se usa una vez para inscribir este equipo)' -AsSecureString
    $tokenBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try {
      $enrollmentToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenBstr)
      if (-not $enrollmentToken) { throw 'A DLP enrollment token is required when a control plane is configured.' }
      $agentId = [guid]::NewGuid().ToString('N').Substring(0, 16)
      $enrollmentUri = $controlPlane.AbsoluteUri.TrimEnd('/') + '/api/dlp/agent/enroll'
      $enrollment = Invoke-RestMethod -Method Post -Uri $enrollmentUri -Headers @{ Authorization = "Bearer $enrollmentToken" } `
        -ContentType 'application/json' -Body (@{ hostname = $env:COMPUTERNAME; agentId = $agentId } | ConvertTo-Json -Compress) -TimeoutSec 20
      if (-not $enrollment.endpointId) { throw 'The DLP control plane did not confirm this endpoint enrollment.' }
      $config.control_plane_url = $controlPlane.AbsoluteUri.TrimEnd('/')
      $config.agent_token = $enrollmentToken
      $config.agent_id = $agentId
    }
    finally {
      $enrollmentToken = $null
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenBstr)
      $secureToken.Dispose()
    }
  }
  $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding utf8
  Set-PrivateAcl -Path $configPath

  $powerShell = (Get-Process -Id $PID).Path
  $runnerPath = Join-Path $releasePath 'ferrispector.ps1'
  $taskArguments = "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File `"$runnerPath`" -Mode Watch -ConfigPath `"$configPath`""
  $action = New-ScheduledTaskAction -Execute $powerShell -Argument $taskArguments
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName 'B89 Ferrispector' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Monitorea las rutas aprobadas con reglas locales YARA-X; detección, sin bloqueo.' -Force | Out-Null
  $wazuhConfigChanged = Add-WazuhFerrispectorLocalfile
  $wazuhService = Get-Service -Name 'WazuhSvc' -ErrorAction Stop
  if ($wazuhConfigChanged -and $wazuhService.Status -eq 'Running') { Restart-Service -Name 'WazuhSvc' -Force }
  elseif ($wazuhService.Status -ne 'Running') { Start-Service -Name 'WazuhSvc' }
  Start-ScheduledTask -TaskName 'B89 Ferrispector'
  Write-Output "Ferrispector installed/updated at $releasePath; configured only for the supplied WatchRoot paths."
}
finally {
  if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
