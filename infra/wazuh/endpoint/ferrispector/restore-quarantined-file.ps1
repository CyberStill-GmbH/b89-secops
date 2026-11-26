[CmdletBinding(DefaultParameterSetName = 'List')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
  [string] $Id,

  [Parameter(ParameterSetName = 'List')]
  [switch] $List,

  [string] $DataRoot = (Join-Path $env:ProgramData 'B89\Ferrispector')
)

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Abre PowerShell como administrador para consultar o restaurar la cuarentena.'
}
. (Join-Path $PSScriptRoot 'rabbitdlp-quarantine.ps1')

if ($PSCmdlet.ParameterSetName -eq 'Restore') {
  $destination = Restore-RabbitDlpQuarantineFile -QuarantineId $Id -DataRoot $DataRoot
  Write-Output "Archivo restaurado y verificado en: $destination"
  exit 0
}

$items = @(Get-RabbitDlpQuarantineItems -DataRoot $DataRoot)
if ($items.Count -eq 0) {
  Write-Output 'No hay archivos en cuarentena.'
  exit 0
}
$items | Select-Object id, created_at, sha256, file_size_bytes, original_path | Format-Table -AutoSize
