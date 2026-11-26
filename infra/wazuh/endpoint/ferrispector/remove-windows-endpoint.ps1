[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$dataRoot = Join-Path $env:ProgramData 'B89\Ferrispector'
$restoreToolsRoot = Join-Path $env:ProgramData 'B89\RabbitDLP'
$usbStatePath = Join-Path $dataRoot 'usb-device-control-state.json'
$preserveUsbState = $false
$hasQuarantine = $false

function Remove-WazuhRabbitDlpLocalfile {
  $agentConfig = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
  if (-not (Test-Path -LiteralPath $agentConfig -PathType Leaf)) { return $false }

  $current = Get-Content -LiteralPath $agentConfig -Raw
  $begin = '<!-- B89:FERRISPECTOR:BEGIN -->'
  $end = '<!-- B89:FERRISPECTOR:END -->'
  $pattern = '(?s)\s*' + [regex]::Escape($begin) + '.*?' + [regex]::Escape($end)
  $updated = [regex]::Replace($current, $pattern, '', 1)
  if ($updated -ceq $current) { return $false }

  $backupPath = $agentConfig + '.rabbitdlp-backup'
  Copy-Item -LiteralPath $agentConfig -Destination $backupPath -Force
  [IO.File]::WriteAllText($agentConfig, $updated, [Text.UTF8Encoding]::new($false))
  return $true
}

foreach ($taskName in @('RabbitDLP', 'B89 Ferrispector')) {
  $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  if (-not $task) { continue }
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$quarantineRecords = Join-Path $dataRoot 'quarantine\records'
$hasQuarantine = (Test-Path -LiteralPath $quarantineRecords -PathType Container) -and
  [bool](Get-ChildItem -LiteralPath $quarantineRecords -Filter '*.json' -File -ErrorAction SilentlyContinue | Select-Object -First 1)

if ((Test-Path -LiteralPath $usbStatePath -PathType Leaf) -and
    (Test-Path -LiteralPath (Join-Path $restoreToolsRoot 'rabbitdlp-device-control.ps1') -PathType Leaf)) {
  try {
    . (Join-Path $restoreToolsRoot 'rabbitdlp-device-control.ps1')
    Remove-RabbitDlpUsbPolicy -DataRoot $dataRoot
  }
  catch {
    $preserveUsbState = $true
    Write-Warning ('RabbitDLP dejó intacta una política USB que otro administrador modificó: ' + $_.Exception.Message)
  }
}

$wazuhChanged = Remove-WazuhRabbitDlpLocalfile
if ($wazuhChanged) {
  $wazuh = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
  if ($wazuh -and $wazuh.Status -eq 'Running') { Restart-Service -Name 'WazuhSvc' -Force }
}

$programRoots = @(
  (Join-Path $env:ProgramFiles 'B89\Ferrispector')
)
foreach ($path in $programRoots) {
  if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
}

if (Test-Path -LiteralPath $dataRoot) {
  if (-not $hasQuarantine -and -not $preserveUsbState) {
    Remove-Item -LiteralPath $dataRoot -Recurse -Force
  }
  else {
    foreach ($child in (Get-ChildItem -LiteralPath $dataRoot -Force)) {
      $keep = ($hasQuarantine -and $child.Name -eq 'quarantine') -or
        ($preserveUsbState -and $child.Name -eq 'usb-device-control-state.json')
      if (-not $keep) { Remove-Item -LiteralPath $child.FullName -Recurse -Force }
    }
  }
}

$diagnosticRoot = Join-Path $env:ProgramData 'B89\RabbitDLP\Logs'
if (Test-Path -LiteralPath $diagnosticRoot) { Remove-Item -LiteralPath $diagnosticRoot -Recurse -Force }
$rabbitDlpProgramDataRoot = Join-Path $env:ProgramData 'B89\RabbitDLP'
if (-not $hasQuarantine -and -not $preserveUsbState -and (Test-Path -LiteralPath $rabbitDlpProgramDataRoot)) {
  Remove-Item -LiteralPath $rabbitDlpProgramDataRoot -Recurse -Force
}
if ((Test-Path -LiteralPath $rabbitDlpProgramDataRoot) -and
    -not (Get-ChildItem -LiteralPath $rabbitDlpProgramDataRoot -Force | Select-Object -First 1)) {
  Remove-Item -LiteralPath $rabbitDlpProgramDataRoot -Force
}

Write-Output 'RabbitDLP was removed. The Wazuh agent and approved folders were kept.'
if ($hasQuarantine) {
  $restoreTool = Join-Path $rabbitDlpProgramDataRoot 'restore-quarantined-file.ps1'
  Write-Output 'La cuarentena quedó preservada. Lista los elementos desde PowerShell como administrador con:'
  Write-Output ('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $restoreTool + '" -List')
}
if ($preserveUsbState) { Write-Output 'Se conservó el estado USB para revisar el conflicto con la política externa antes de limpiar Defender.' }
Write-Output 'Revoke the endpoint credential from DLP de endpoints if this computer must be disconnected remotely.'
