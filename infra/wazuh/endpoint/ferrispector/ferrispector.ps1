[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('Watch', 'Scan')]
  [string] $Mode,

  [Parameter(Mandatory = $true)]
  [string] $ConfigPath,

  [string] $ScanPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
. (Join-Path $PSScriptRoot 'rabbitdlp-device-control.ps1')
. (Join-Path $PSScriptRoot 'rabbitdlp-quarantine.ps1')

function Write-FerrispectorEvent {
  param([Parameter(Mandatory = $true)][hashtable] $Event)
  $Event['observed_at'] = [DateTime]::UtcNow.ToString('o')
  $line = $Event | ConvertTo-Json -Compress -Depth 6
  Add-Content -LiteralPath $script:EventPath -Value $line -Encoding utf8
}

function Invoke-FerrispectorScan {
  param([Parameter(Mandatory = $true)][string] $Path)
  $fullPath = [IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { return }
  if ($script:ControlPlaneUrl -and -not $script:RemotePolicyReady) { return }
  $item = Get-Item -LiteralPath $fullPath -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return }

  $fileHash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $fingerprintEvent = $null
  if ($script:FingerprintSet.ContainsKey($fileHash)) {
    $fingerprintEvent = @{
      integration = 'b89_ferrispector'
      event_type = 'match'
      endpoint = $env:COMPUTERNAME
      yara_rule_id = 'B89_DLP_EXACT_FILE_FINGERPRINT'
      file_sha256 = $fileHash
      file_extension = $item.Extension.ToLowerInvariant()
      file_size_bytes = [long]$item.Length
      policy_sha256 = $script:PolicyHash
    }
  }

  $ruleEvents = [Collections.Generic.List[hashtable]]::new()
  $output = @(& $script:YaraPath scan --compiled-rules $script:RulesPath --output-format=ndjson -m -g $fullPath 2>$null)
  $exitCode = $LASTEXITCODE
  if ($exitCode -ne 0) {
    Write-FerrispectorEvent @{
      integration = 'b89_ferrispector'
      event_type = 'scan_error'
      file_sha256 = $fileHash
      file_extension = $item.Extension.ToLowerInvariant()
      error_code = 'YARA_X_SCAN_FAILED'
    }
  } else { foreach ($line in $output) {
    if (-not ($line -is [string]) -or [string]::IsNullOrWhiteSpace($line)) { continue }
    try { $result = $line | ConvertFrom-Json -ErrorAction Stop }
    catch {
      Write-FerrispectorEvent @{
        integration = 'b89_ferrispector'
        event_type = 'scan_error'
        file_sha256 = $fileHash
        file_extension = $item.Extension.ToLowerInvariant()
        error_code = 'YARA_X_OUTPUT_INVALID'
      }
      continue
    }
    $ruleIds = @($result.rules | ForEach-Object { $_.identifier } | Where-Object { $_ })
    $ruleIds = @($ruleIds | Where-Object { $script:EnabledRuleIds.ContainsKey([string]$_) })
    if ($ruleIds.Count -eq 0) { continue }
    foreach ($ruleId in $ruleIds) {
      $ruleEvents.Add(@{
        integration = 'b89_ferrispector'
        event_type = 'match'
        endpoint = $env:COMPUTERNAME
        yara_rule_id = [string]$ruleId
        file_sha256 = $fileHash
        file_extension = $item.Extension.ToLowerInvariant()
        file_size_bytes = [long]$item.Length
        policy_sha256 = $script:PolicyHash
      })
    }
  } }

  if ($fingerprintEvent) {
    if ($script:QuarantineExactFingerprints) {
      $result = Move-RabbitDlpFileToQuarantine -Path $fullPath -Sha256 $fileHash -DataRoot $script:DataRoot
      $fingerprintEvent['quarantine_status'] = $result.status
      if ($result.id) { $fingerprintEvent['quarantine_id'] = $result.id }
      $fingerprintEvent['action_code'] = $result.code
    } else { $fingerprintEvent['quarantine_status'] = 'disabled' }
    Write-FerrispectorEvent $fingerprintEvent
  }
  foreach ($event in $ruleEvents) { Write-FerrispectorEvent $event }
}

function Set-FerrispectorPolicyState {
  param(
    [Parameter(Mandatory = $true)][string[]] $EnabledRuleIds,
    [Parameter(Mandatory = $true)][string[]] $Fingerprints,
    [Parameter(Mandatory = $true)][bool] $QuarantineExactFingerprints,
    [Parameter(Mandatory = $true)]$UsbControl,
    [Parameter(Mandatory = $true)][int] $Revision,
    [Parameter(Mandatory = $true)][string] $Version
  )
  # Must match DLP_RULE_IDS in the API. An advanced rule enabled in the console used to be
  # rejected here, so Windows endpoints never acknowledged and stayed "updating" forever.
  $knownRules = @(
    'B89_CRED_PRIVATE_KEY_PEM', 'B89_CRED_GITHUB_TOKEN', 'B89_CRED_SLACK_TOKEN',
    'B89_CRED_GOOGLE_API_KEY', 'B89_CRED_AZURE_STORAGE_KEY', 'B89_CRED_OPENAI_API_KEY',
    'B89_CRED_AWS_ACCESS_KEY_PAIR', 'B89_SECRET_DATABASE_CONNECTION',
    'B89_SECRET_CREDENTIAL_ASSIGNMENT', 'B89_PII_PERU_DNI_CONTEXTUAL',
    'B89_PII_PERU_RUC_CONTEXTUAL'
  )
  if ($EnabledRuleIds.Count -gt $knownRules.Count -or @($EnabledRuleIds | Where-Object { $_ -notin $knownRules }).Count -gt 0) {
    throw 'The DLP policy contains an unsupported rule ID.'
  }
  if ($Fingerprints.Count -gt 100000 -or @($Fingerprints | Where-Object { $_ -notmatch '^[0-9a-fA-F]{64}$' }).Count -gt 0) {
    throw 'The DLP policy fingerprint catalog is invalid or too large.'
  }
  $script:EnabledRuleIds = @{}
  foreach ($ruleId in $EnabledRuleIds) { $script:EnabledRuleIds[[string]$ruleId] = $true }
  $script:FingerprintSet = @{}
  foreach ($hash in $Fingerprints) { $script:FingerprintSet[[string]$hash.ToLowerInvariant()] = $true }
  $script:QuarantineExactFingerprints = $QuarantineExactFingerprints
  $script:UsbControlPolicy = $UsbControl
  $script:PolicyRevision = $Revision
  $script:PolicyVersion = $Version
  $canonical = @($script:RulesHash, $script:PolicyVersion, ($EnabledRuleIds | Sort-Object), ($Fingerprints | Sort-Object)) -join "`n"
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $script:PolicyHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))).Replace('-', '')).ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Sync-FerrispectorPolicy {
  if (-not $script:ControlPlaneUrl -or -not $script:AgentToken) { return }
  $script:LastPolicyAttemptAt = [DateTime]::UtcNow
  try {
    $headers = @{ Authorization = "Bearer $script:AgentToken" }
    $policyUri = $script:ControlPlaneUrl.TrimEnd('/') + '/api/dlp/agent/policy'
    $policy = Invoke-RestMethod -Method Get -Uri $policyUri -Headers $headers -TimeoutSec 20
    if ($policy.policy) { $policy = $policy.policy }
    $revision = 0
    if (-not [int]::TryParse([string]$policy.revision, [ref]$revision) -or $revision -lt 0 -or
        -not ($policy.policyVersion -is [string]) -or $policy.policyVersion.Length -gt 64 -or
        -not ($policy.enabledRuleIds -is [array]) -or -not ($policy.fingerprintsSha256 -is [array]) -or
        -not ($policy.quarantineExactFingerprints -is [bool]) -or -not ($policy.usbControl.enabled -is [bool]) -or
        -not ($policy.usbControl.allowedGroups -is [array])) {
      throw 'DLP policy response has an unsupported format.'
    }
    $policyChanged = $revision -ne $script:PolicyRevision
    Set-FerrispectorPolicyState -EnabledRuleIds $policy.enabledRuleIds -Fingerprints $policy.fingerprintsSha256 `
      -QuarantineExactFingerprints $policy.quarantineExactFingerprints -UsbControl $policy.usbControl `
      -Revision $revision -Version $policy.policyVersion
    try {
      $script:UsbControlStatus = Set-RabbitDlpUsbPolicy -Policy $script:UsbControlPolicy -DataRoot $script:DataRoot
    }
    catch { $script:UsbControlStatus = @{ status = 'error'; code = 'DEFENDER_APPLY_FAILED' } }

    $fingerprintBody = @('# Managed by B89 DLP policy revision ' + $script:PolicyRevision) + @($policy.fingerprintsSha256 | ForEach-Object { $_.ToLowerInvariant() })
    $fingerprintTemporary = $script:FingerprintCatalogPath + '.sync'
    [IO.File]::WriteAllLines($fingerprintTemporary, $fingerprintBody, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $fingerprintTemporary -Destination $script:FingerprintCatalogPath -Force

    # Rescan before the ack: if the ack fails, the next sync no longer sees a revision change.
    if ($policyChanged -and $script:LastScanned -and $script:LastScanned.Count -gt 0) {
      $script:LastScanned.Clear()
      $script:PolicyRescanNeeded = $true
    }
    $script:RemotePolicyReady = $true
    $ackUri = $script:ControlPlaneUrl.TrimEnd('/') + '/api/dlp/agent/ack'
    $ackBody = @{
      revision = $script:PolicyRevision
      policyVersion = $script:PolicyVersion
      usbControl = $script:UsbControlStatus
    } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Post -Uri $ackUri -Headers $headers -ContentType 'application/json' -Body $ackBody -TimeoutSec 20 | Out-Null
    $script:LastPolicySyncAt = [DateTime]::UtcNow
  }
  catch {
    Write-FerrispectorEvent @{
      integration = 'b89_ferrispector'
      event_type = 'policy_sync_error'
      error_code = 'DLP_POLICY_UNAVAILABLE'
    }
  }
}

function Invoke-FerrispectorReconciliation {
  foreach ($root in $script:WatchRoots) {
    Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
      if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return }
      $path = $_.FullName
      $signature = "$($_.Length):$($_.LastWriteTimeUtc.Ticks)"
      if ($script:LastScanned[$path] -eq $signature) { return }
      try {
        Invoke-FerrispectorScan -Path $path
        $script:LastScanned[$path] = $signature
      }
      catch {
        Write-FerrispectorEvent @{
          integration = 'b89_ferrispector'
          event_type = 'scan_error'
          file_sha256 = ''
          error_code = 'FILE_SCAN_FAILED'
        }
      }
    }
  }
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw 'Ferrispector configuration is missing.' }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop
if ($config.schema_version -ne 2) { throw 'Ferrispector config v1 uses a reusable enrollment secret. Re-run the installer with a fresh enrollment token.' }
$script:YaraPath = Join-Path $PSScriptRoot 'bin\yr.exe'
$script:RulesPath = [IO.Path]::GetFullPath([string]$config.rules_path)
$script:EventPath = [IO.Path]::GetFullPath([string]$config.events_path)
$script:FingerprintCatalogPath = [IO.Path]::GetFullPath([string]$config.fingerprints_path)
$script:DataRoot = Split-Path -Parent ([IO.Path]::GetFullPath($ConfigPath))
$script:RulesHash = (Get-FileHash -LiteralPath $script:RulesPath -Algorithm SHA256).Hash.ToLowerInvariant()
$script:ControlPlaneUrl = [string]$config.control_plane_url
$script:AgentToken = [string]$config.agent_credential
$script:LastPolicySyncAt = [DateTime]::MinValue
$script:LastPolicyAttemptAt = [DateTime]::MinValue
$script:RemotePolicyReady = -not [bool]$script:ControlPlaneUrl
$script:QuarantineExactFingerprints = $false
$script:UsbControlPolicy = @{ enabled = $false; supportedPlanConfirmed = $false; allowedGroups = @() }
$script:UsbControlStatus = @{ status = 'disabled'; code = 'POLICY_DISABLED' }
if (-not (Test-Path -LiteralPath $script:YaraPath -PathType Leaf)) { throw 'YARA-X engine is missing.' }
if (-not (Test-Path -LiteralPath $script:RulesPath -PathType Leaf)) { throw 'YARA DLP policy file is missing.' }
$script:PolicyHash = (Get-FileHash -LiteralPath $script:RulesPath -Algorithm SHA256).Hash.ToLowerInvariant()
$script:EnabledRuleIds = @{
  'B89_CRED_PRIVATE_KEY_PEM' = $true
  'B89_CRED_GITHUB_TOKEN' = $true
  'B89_CRED_SLACK_TOKEN' = $true
  'B89_CRED_GOOGLE_API_KEY' = $true
  'B89_CRED_AZURE_STORAGE_KEY' = $true
  'B89_CRED_OPENAI_API_KEY' = $true
}
$script:FingerprintSet = @{}
foreach ($line in (Get-Content -LiteralPath $script:FingerprintCatalogPath -ErrorAction Stop)) {
  $fingerprint = $line.Trim()
  if (-not $fingerprint -or $fingerprint.StartsWith('#')) { continue }
  if ($fingerprint -notmatch '^[0-9a-fA-F]{64}$') { throw 'The local fingerprint catalog contains an invalid SHA-256 value.' }
  $script:FingerprintSet[$fingerprint.ToLowerInvariant()] = $true
}
if (-not $script:ControlPlaneUrl) {
  Set-FerrispectorPolicyState -EnabledRuleIds @($script:EnabledRuleIds.Keys) `
    -Fingerprints @($script:FingerprintSet.Keys) -QuarantineExactFingerprints $false `
    -UsbControl $script:UsbControlPolicy -Revision 0 -Version '1.0.0'
}
New-Item -ItemType Directory -Path (Split-Path -Parent $script:EventPath) -Force | Out-Null

if ($Mode -eq 'Scan') {
  if (-not $ScanPath) { throw 'ScanPath is required in Scan mode.' }
  Invoke-FerrispectorScan -Path $ScanPath
  exit 0
}

$roots = @($config.watch_roots | ForEach-Object { [IO.Path]::GetFullPath([string]$_) } | Select-Object -Unique)
if ($roots.Count -eq 0) { throw 'At least one explicitly approved watch root is required.' }
$script:WatchRoots = $roots
$script:LastScanned = @{}
$script:ReconcileSentinel = '__B89_FERRISPECTOR_RECONCILE__'
$reconcileMinutes = 60
if ($config.reconcile_interval_minutes -is [int] -and $config.reconcile_interval_minutes -ge 5 -and $config.reconcile_interval_minutes -le 1440) {
  $reconcileMinutes = [int]$config.reconcile_interval_minutes
}
$pending = [System.Collections.Concurrent.BlockingCollection[string]]::new(1000)
$watchers = [Collections.Generic.List[IO.FileSystemWatcher]]::new()
$subscriptions = [Collections.Generic.List[object]]::new()
try {
  foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Watch root does not exist: $root" }
    $watcher = [IO.FileSystemWatcher]::new($root)
    $watcher.IncludeSubdirectories = [bool]$config.include_subdirectories
    $watcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::LastWrite -bor [IO.NotifyFilters]::Size
    $watcher.InternalBufferSize = 65536
    foreach ($eventName in @('Created', 'Changed', 'Renamed')) {
      $identifier = 'Ferrispector-' + [guid]::NewGuid().ToString('N')
      $subscription = Register-ObjectEvent -InputObject $watcher -EventName $eventName -SourceIdentifier $identifier -MessageData $pending -Action {
        $eventPath = $Event.SourceEventArgs.FullPath
        try { $Event.MessageData.Add($eventPath, [Threading.CancellationToken]::None) } catch { }
      }
      $subscriptions.Add($subscription)
    }
    $identifier = 'Ferrispector-' + [guid]::NewGuid().ToString('N')
    $subscription = Register-ObjectEvent -InputObject $watcher -EventName Error -SourceIdentifier $identifier -MessageData $pending -Action {
      try { $Event.MessageData.Add('__B89_FERRISPECTOR_RECONCILE__', [Threading.CancellationToken]::None) } catch { }
    }
    $subscriptions.Add($subscription)
    $watchers.Add($watcher)
    $watcher.EnableRaisingEvents = $true
  }

  # Scan the approved roots once at startup and reconcile periodically so an event missed
  # during a buffer overflow or restart is found on the next pass.
  Sync-FerrispectorPolicy
  Invoke-FerrispectorReconciliation
  $lastReconciliation = [DateTime]::UtcNow
  $script:PolicyRescanNeeded = $false
  while ($true) {
    $path = $null
    if (-not $pending.TryTake([ref]$path, 1000)) {
      if (([DateTime]::UtcNow - $script:LastPolicyAttemptAt).TotalSeconds -ge 30) { Sync-FerrispectorPolicy }
      if ($script:PolicyRescanNeeded) {
        Invoke-FerrispectorReconciliation
        $script:PolicyRescanNeeded = $false
        $lastReconciliation = [DateTime]::UtcNow
      }
      if (([DateTime]::UtcNow - $lastReconciliation).TotalMinutes -ge $reconcileMinutes) {
        Invoke-FerrispectorReconciliation
        $lastReconciliation = [DateTime]::UtcNow
      }
      continue
    }
    if ($path -eq $script:ReconcileSentinel) {
      Write-FerrispectorEvent @{
        integration = 'b89_ferrispector'
        event_type = 'watcher_resync'
        error_code = 'WATCHER_BUFFER_OVERFLOW'
      }
      Invoke-FerrispectorReconciliation
      $lastReconciliation = [DateTime]::UtcNow
      continue
    }
    if (([DateTime]::UtcNow - $script:LastPolicyAttemptAt).TotalSeconds -ge 30) { Sync-FerrispectorPolicy }
    Start-Sleep -Milliseconds 800
    $nextPath = ''
    while ($pending.TryTake([ref]$nextPath, 50)) { $path = $nextPath; $nextPath = '' }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    try {
      $item = Get-Item -LiteralPath $path -Force
      $signature = "$($item.Length):$($item.LastWriteTimeUtc.Ticks)"
      if ($script:LastScanned[$path] -eq $signature) { continue }
      Invoke-FerrispectorScan -Path $path
      $script:LastScanned[$path] = $signature
    } catch {
      Write-FerrispectorEvent @{
        integration = 'b89_ferrispector'
        event_type = 'scan_error'
        file_sha256 = ''
        error_code = 'FILE_SCAN_FAILED'
      }
    }
  }
}
finally {
  foreach ($watcher in $watchers) { $watcher.EnableRaisingEvents = $false; $watcher.Dispose() }
  foreach ($subscription in $subscriptions) { Unregister-Event -SourceIdentifier $subscription.SourceIdentifier -ErrorAction SilentlyContinue }
  $pending.Dispose()
}
