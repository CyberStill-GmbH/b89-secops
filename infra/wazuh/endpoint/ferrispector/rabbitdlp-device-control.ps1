function Get-RabbitDlpUsbValues {
  param([string] $GroupsXml, [string] $RulesXml)
  return @(
    @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features'; name = 'DeviceControlEnabled'; type = 'DWord'; data = 1 },
    @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Device Control'; name = 'DefaultEnforcement'; type = 'DWord'; data = 1 },
    @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Device Control'; name = 'SecuredDevicesConfiguration'; type = 'String'; data = 'RemovableMediaDevices' },
    @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Device Control\Policy Groups'; name = 'PolicyGroups'; type = 'String'; data = $GroupsXml },
    @{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Device Control\Policy Rules'; name = 'PolicyRules'; type = 'String'; data = $RulesXml }
  )
}

function Test-RabbitDlpUsbValueEqual {
  param($Expected)
  if (-not (Test-Path -LiteralPath $Expected.path)) { return $false }
  $actual = Get-ItemProperty -LiteralPath $Expected.path -Name $Expected.name -ErrorAction SilentlyContinue
  if (-not $actual) { return $false }
  $value = $actual.($Expected.name)
  if ($Expected.type -eq 'String') { return [string]$value -ceq [string]$Expected.data }
  return [int]$value -eq [int]$Expected.data
}

function Set-RabbitDlpUsbValue {
  param($Value)
  New-Item -Path $Value.path -Force | Out-Null
  if (Get-ItemProperty -LiteralPath $Value.path -Name $Value.name -ErrorAction SilentlyContinue) {
    Set-ItemProperty -LiteralPath $Value.path -Name $Value.name -Value $Value.data -Force
  }
  else {
    New-ItemProperty -LiteralPath $Value.path -Name $Value.name -Value $Value.data -PropertyType $Value.type -Force | Out-Null
  }
}

function Remove-RabbitDlpUsbValue {
  param($Value)
  if (Test-Path -LiteralPath $Value.path) {
    Remove-ItemProperty -LiteralPath $Value.path -Name $Value.name -ErrorAction SilentlyContinue
  }
}

function Get-RabbitDlpUsbXml {
  param([Parameter(Mandatory = $true)]$Policy)
  if (-not $Policy.enabled -or -not $Policy.supportedPlanConfirmed -or
      @($Policy.allowedGroups).Count -eq 0) {
    throw 'B89 USB policy is not confirmed or has no authorized group.'
  }
  $allMediaId = '{d8819053-24f4-444a-a0fb-9ce5a9e97862}'
  $ruleId = '{7beca8fe-313a-46f2-a090-399eb3d74318}'
  $identityEntries = [Collections.Generic.List[string]]::new()
  $allowedSids = @($Policy.allowedGroups | ForEach-Object { $_.identities } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
  foreach ($sid in $allowedSids) {
    # Device Control supports one SID condition per entry. The API constrains this value to
    # a Windows SID; Entra object IDs need Graph resolution, which this service does not have.
    if ($sid -notmatch '^S-1-(?:\d+-){1,14}\d+$') { throw 'B89 USB policy contains an invalid Windows SID.' }
    # Stable IDs prevent Defender from seeing a fresh policy on every 30-second sync.
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $digest = $hash.ComputeHash([Text.Encoding]::UTF8.GetBytes('rabbitdlp-usb-allow:' + $sid.ToUpperInvariant())) }
    finally { $hash.Dispose() }
    $hex = [BitConverter]::ToString($digest, 0, 16).Replace('-', '').ToLowerInvariant()
    $entryId = '{' + $hex.Substring(0, 8) + '-' + $hex.Substring(8, 4) + '-' + $hex.Substring(12, 4) + '-' + $hex.Substring(16, 4) + '-' + $hex.Substring(20, 12) + '}'
    $identityEntries.Add("<Entry Id=`"$entryId`"><Type>Allow</Type><AccessMask>63</AccessMask><Options>0</Options><Sid>$sid</Sid></Entry>")
  }
  $denyId = '{6d730a61-21ed-4a40-a5ee-083f4b4a3715}'
  $auditId = '{87f90bd7-bced-49e5-afdd-227eb5cf74d4}'
  $groupsXml = "<PolicyGroups><Group Id=`"$allMediaId`" Type=`"Device`"><Name>RabbitDLP removable storage</Name><MatchType>MatchAny</MatchType><DescriptorIdList><PrimaryId>RemovableMediaDevices</PrimaryId></DescriptorIdList></Group></PolicyGroups>"
  $entries = ($identityEntries -join '') +
    "<Entry Id=`"$denyId`"><Type>Deny</Type><AccessMask>63</AccessMask><Options>0</Options></Entry>" +
    "<Entry Id=`"$auditId`"><Type>AuditDenied</Type><AccessMask>63</AccessMask><Options>3</Options></Entry>"
  $rulesXml = "<PolicyRules><PolicyRule Id=`"$ruleId`"><Name>RabbitDLP USB access by SOC group</Name><IncludedIdList><GroupId>$allMediaId</GroupId></IncludedIdList><ExcludedIdList></ExcludedIdList>$entries</PolicyRule></PolicyRules>"
  return @{ groups = $groupsXml; rules = $rulesXml }
}

function Get-RabbitDlpDefenderUsbStatus {
  try {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
      return @{ status = 'unsupported'; code = 'DEFENDER_UNAVAILABLE' }
    }
    $status = Get-MpComputerStatus -ErrorAction Stop
    if ([string]$status.DeviceControlState -ne 'Enabled' -or
        [string]$status.DeviceControlDefaultEnforcement -ne 'DefaultAllow' -or
        -not $status.DeviceControlPoliciesLastUpdated) {
      return @{ status = 'pending'; code = 'POLICY_PENDING' }
    }
    return @{ status = 'active'; code = 'POLICY_ACTIVE' }
  }
  catch {
    return @{ status = 'unsupported'; code = 'DEFENDER_UNAVAILABLE' }
  }
}

function Get-RabbitDlpUsbAppliedStatus {
  param([string] $AppliedAt)
  $defender = Get-RabbitDlpDefenderUsbStatus
  if ($defender.status -ne 'active') { return $defender }
  try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    if (-not $AppliedAt -or -not $status.DeviceControlPoliciesLastUpdated -or
        [DateTime]$status.DeviceControlPoliciesLastUpdated -lt [DateTime]$AppliedAt) {
      return @{ status = 'pending'; code = 'POLICY_PENDING' }
    }
  }
  catch { return @{ status = 'pending'; code = 'POLICY_PENDING' } }
  return $defender
}

function Get-RabbitDlpCurrentUsbValue {
  param($Expected)
  if (-not (Test-Path -LiteralPath $Expected.path)) { return $null }
  $actual = Get-ItemProperty -LiteralPath $Expected.path -Name $Expected.name -ErrorAction SilentlyContinue
  if (-not $actual) { return $null }
  return $actual.($Expected.name)
}

function Restore-RabbitDlpUsbSnapshot {
  param(
    [Parameter(Mandatory = $true)]$Pending,
    [Parameter(Mandatory = $true)][array]$Previous
  )
  foreach ($value in $Pending) {
    $prior = $Previous | Where-Object { $_.path -eq $value.path -and $_.name -eq $value.name } | Select-Object -First 1
    $current = Get-RabbitDlpCurrentUsbValue -Expected $value
    if ($null -eq $current) { continue }
    if (Test-RabbitDlpUsbValueEqual -Expected $value) {
      if ($prior) { Set-RabbitDlpUsbValue -Value $prior }
      else { Remove-RabbitDlpUsbValue -Value $value }
    }
    elseif ($prior -and (Test-RabbitDlpUsbValueEqual -Expected $prior)) { continue }
    else { throw 'Una política externa cambió durante la aplicación USB; se dejó intacta.' }
  }
  foreach ($value in $Previous) {
    if (-not (Test-RabbitDlpUsbValueEqual -Expected $value)) { Set-RabbitDlpUsbValue -Value $value }
  }
}

function Set-RabbitDlpUsbPolicy {
  param(
    [Parameter(Mandatory = $true)]$Policy,
    [Parameter(Mandatory = $true)][string] $DataRoot
  )
  $statePath = Join-Path $DataRoot 'usb-device-control-state.json'
  if (-not $Policy.enabled) {
    Remove-RabbitDlpUsbPolicy -DataRoot $DataRoot
    return @{ status = 'disabled'; code = 'POLICY_DISABLED' }
  }
  $version = [Environment]::OSVersion.Version
  if ($version.Major -ne 10 -or $version.Build -lt 17763) {
    return @{ status = 'unsupported'; code = 'WINDOWS_UNSUPPORTED' }
  }
  if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
    return @{ status = 'unsupported'; code = 'DEFENDER_UNAVAILABLE' }
  }
  $mdmRoot = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender'
  $mdmProperties = if (Test-Path -LiteralPath $mdmRoot) { Get-ItemProperty -LiteralPath $mdmRoot -ErrorAction SilentlyContinue } else { $null }
  $managedDeviceControl = $false
  if ($mdmProperties) {
    foreach ($name in @('DeviceControlEnabled', 'DefaultEnforcement', 'SecuredDevicesConfiguration')) {
      if ($mdmProperties.PSObject.Properties.Name -contains $name) { $managedDeviceControl = $true }
    }
  }
  if ($managedDeviceControl -or (Test-Path -LiteralPath (Join-Path $mdmRoot 'DeviceControl'))) {
    return @{ status = 'conflict'; code = 'DEFENDER_POLICY_CONFLICT' }
  }
  $xml = Get-RabbitDlpUsbXml -Policy $Policy
  $desired = Get-RabbitDlpUsbValues -GroupsXml $xml.groups -RulesXml $xml.rules
  $state = $null
  $previousApplied = @()
  $previousAppliedAt = $null
  if (Test-Path -LiteralPath $statePath -PathType Leaf) {
    try { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { return @{ status = 'error'; code = 'DEFENDER_APPLY_FAILED' } }
    if ($state.owner -ne 'rabbitdlp' -or -not ($state.lastApplied -is [array])) {
      return @{ status = 'conflict'; code = 'DEFENDER_POLICY_CONFLICT' }
    }
    if ($state.applyState -eq 'pending') {
      $pendingApplied = @($state.lastApplied)
      $previousApplied = @($state.previousApplied)
      $previousAppliedAt = $state.previousAppliedAt
      try { Restore-RabbitDlpUsbSnapshot -Pending $pendingApplied -Previous $previousApplied }
      catch { return @{ status = 'conflict'; code = 'DEFENDER_POLICY_CONFLICT' } }
      if ($previousApplied.Count -gt 0) {
        $state = [ordered]@{
          owner = 'rabbitdlp'; original = @(); lastApplied = $previousApplied
          appliedAt = $previousAppliedAt; applyState = 'applied'; previousApplied = @(); previousAppliedAt = $null
        }
        $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($statePath + '.tmp') -Encoding utf8
        Move-Item -LiteralPath ($statePath + '.tmp') -Destination $statePath -Force
      }
      else {
        Remove-Item -LiteralPath $statePath -Force
        $state = $null
      }
    }
  }
  if ($state) {
    if (-not ($state.lastApplied -is [array])) { return @{ status = 'conflict'; code = 'DEFENDER_POLICY_CONFLICT' } }
    foreach ($previous in $state.lastApplied) {
      if (-not (Test-RabbitDlpUsbValueEqual -Expected $previous)) {
        return @{ status = 'conflict'; code = 'DEFENDER_POLICY_CONFLICT' }
      }
    }
    $previousApplied = @($state.lastApplied)
    $previousAppliedAt = $state.appliedAt
  }
  else {
    foreach ($candidate in $desired) {
      if ($null -ne (Get-RabbitDlpCurrentUsbValue -Expected $candidate)) {
        return @{ status = 'conflict'; code = 'DEFENDER_POLICY_CONFLICT' }
      }
    }
  }
  $alreadyApplied = $true
  foreach ($candidate in $desired) {
    if (-not (Test-RabbitDlpUsbValueEqual -Expected $candidate)) { $alreadyApplied = $false; break }
  }
  if ($state -and $alreadyApplied) { return Get-RabbitDlpUsbAppliedStatus -AppliedAt ([string]$state.appliedAt) }

  $appliedAt = [DateTime]::UtcNow.ToString('o')
  $pendingState = [ordered]@{
    owner = 'rabbitdlp'; original = @(); lastApplied = $desired; appliedAt = $appliedAt
    applyState = 'pending'; previousApplied = $previousApplied; previousAppliedAt = $previousAppliedAt
  }
  try {
    $pendingState | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($statePath + '.tmp') -Encoding utf8
    Move-Item -LiteralPath ($statePath + '.tmp') -Destination $statePath -Force
    foreach ($value in $desired) { Set-RabbitDlpUsbValue -Value $value }
    foreach ($value in $desired) {
      if (-not (Test-RabbitDlpUsbValueEqual -Expected $value)) { throw 'Windows no confirmó todos los valores de Device Control.' }
    }
    $appliedState = [ordered]@{
      owner = 'rabbitdlp'; original = @(); lastApplied = $desired; appliedAt = $appliedAt
      applyState = 'applied'; previousApplied = @(); previousAppliedAt = $null
    }
    $appliedState | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($statePath + '.tmp') -Encoding utf8
    Move-Item -LiteralPath ($statePath + '.tmp') -Destination $statePath -Force
    return Get-RabbitDlpUsbAppliedStatus -AppliedAt $appliedAt
  }
  catch {
    try {
      Restore-RabbitDlpUsbSnapshot -Pending $desired -Previous $previousApplied
      if ($previousApplied.Count -gt 0) {
        $restoredState = [ordered]@{
          owner = 'rabbitdlp'; original = @(); lastApplied = $previousApplied
          appliedAt = $previousAppliedAt; applyState = 'applied'; previousApplied = @(); previousAppliedAt = $null
        }
        $restoredState | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($statePath + '.tmp') -Encoding utf8
        Move-Item -LiteralPath ($statePath + '.tmp') -Destination $statePath -Force
      }
      else { Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue }
    }
    catch { }
    return @{ status = 'error'; code = 'DEFENDER_APPLY_FAILED' }
  }
}

function Remove-RabbitDlpUsbPolicy {
  param([Parameter(Mandatory = $true)][string] $DataRoot)
  $statePath = Join-Path $DataRoot 'usb-device-control-state.json'
  if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return }
  $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -ErrorAction Stop
  if ($state.owner -ne 'rabbitdlp' -or -not ($state.lastApplied -is [array])) {
    throw 'RabbitDLP cannot safely remove a USB policy it does not own.'
  }
  if ($state.applyState -eq 'pending') {
    $previousApplied = @($state.previousApplied)
    Restore-RabbitDlpUsbSnapshot -Pending @($state.lastApplied) -Previous $previousApplied
    if ($previousApplied.Count -eq 0) {
      Remove-Item -LiteralPath $statePath -Force
      return
    }
    $state = [ordered]@{
      owner = 'rabbitdlp'; original = @(); lastApplied = $previousApplied
      appliedAt = $state.previousAppliedAt; applyState = 'applied'; previousApplied = @(); previousAppliedAt = $null
    }
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($statePath + '.tmp') -Encoding utf8
    Move-Item -LiteralPath ($statePath + '.tmp') -Destination $statePath -Force
  }
  foreach ($previous in $state.lastApplied) {
    if (-not (Test-RabbitDlpUsbValueEqual -Expected $previous)) {
      throw 'A different Windows policy replaced RabbitDLP USB settings; review the local Defender policy before removal.'
    }
  }
  foreach ($previous in $state.lastApplied) { Remove-RabbitDlpUsbValue -Value $previous }
  foreach ($previous in $state.lastApplied) {
    if ($null -ne (Get-RabbitDlpCurrentUsbValue -Expected $previous)) {
      throw 'Windows no confirmó la retirada de toda la política USB de RabbitDLP.'
    }
  }
  Remove-Item -LiteralPath $statePath -Force
}
