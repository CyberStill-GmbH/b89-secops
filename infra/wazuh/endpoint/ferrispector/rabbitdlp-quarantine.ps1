function Set-RabbitDlpPrivateDirectory {
  param([Parameter(Mandatory = $true)][string] $Path)
  New-Item -ItemType Directory -Path $Path -Force | Out-Null
  & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'No se pudieron restringir los permisos de la cuarentena a SYSTEM y Administradores.' }
}

function Write-RabbitDlpQuarantineRecord {
  param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)]$Record)
  $temporary = $Path + '.tmp'
  [IO.File]::WriteAllText($temporary, ($Record | ConvertTo-Json -Compress -Depth 5), [Text.UTF8Encoding]::new($false))
  Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Move-RabbitDlpFileToQuarantine {
  param(
    [Parameter(Mandatory = $true)][string] $Path,
    [Parameter(Mandatory = $true)][string] $Sha256,
    [Parameter(Mandatory = $true)][string] $DataRoot
  )
  $root = Join-Path $DataRoot 'quarantine'
  $objects = Join-Path $root 'objects'
  $records = Join-Path $root 'records'
  Set-RabbitDlpPrivateDirectory -Path $objects
  Set-RabbitDlpPrivateDirectory -Path $records
  $id = [guid]::NewGuid().ToString('N')
  $objectPath = Join-Path $objects ($id + '.bin')
  $recordPath = Join-Path $records ($id + '.json')
  $temporaryObject = $objectPath + '.tmp'
  $originalPath = [IO.Path]::GetFullPath($Path)
  try {
    $current = Get-FileHash -LiteralPath $originalPath -Algorithm SHA256 -ErrorAction Stop
    if ($current.Hash.ToLowerInvariant() -ne $Sha256) { return @{ status = 'failed'; id = $null; code = 'FILE_CHANGED' } }
    $originalAcl = (Get-Acl -LiteralPath $originalPath -ErrorAction Stop).Sddl
    Copy-Item -LiteralPath $originalPath -Destination $temporaryObject -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $temporaryObject -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Sha256) {
      Remove-Item -LiteralPath $temporaryObject -Force -ErrorAction SilentlyContinue
      return @{ status = 'failed'; id = $null; code = 'QUARANTINE_VERIFY_FAILED' }
    }
    Move-Item -LiteralPath $temporaryObject -Destination $objectPath -ErrorAction Stop
    $record = @{
      id = $id
      sha256 = $Sha256
      original_path = $originalPath
      original_acl_sddl = $originalAcl
      file_size_bytes = (Get-Item -LiteralPath $objectPath).Length
      created_at = [DateTime]::UtcNow.ToString('o')
      state = 'pending-delete'
    }
    Write-RabbitDlpQuarantineRecord -Path $recordPath -Record $record
    if ((Get-FileHash -LiteralPath $originalPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -ne $Sha256) {
      Remove-Item -LiteralPath $recordPath -Force -ErrorAction SilentlyContinue
      Remove-Item -LiteralPath $objectPath -Force -ErrorAction SilentlyContinue
      return @{ status = 'failed'; id = $null; code = 'FILE_CHANGED' }
    }
    Remove-Item -LiteralPath $originalPath -Force -ErrorAction Stop
    $record.state = 'quarantined'
    try { Write-RabbitDlpQuarantineRecord -Path $recordPath -Record $record } catch { }
    return @{ status = 'quarantined'; id = $id; code = 'QUARANTINED' }
  }
  catch {
    Remove-Item -LiteralPath $temporaryObject -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
      Remove-Item -LiteralPath $objectPath -Force -ErrorAction SilentlyContinue
    }
    return @{ status = 'failed'; id = $null; code = 'QUARANTINE_IO_FAILED' }
  }
}

function Get-RabbitDlpQuarantineItems {
  param([Parameter(Mandatory = $true)][string] $DataRoot)
  $records = Join-Path $DataRoot 'quarantine\records'
  if (-not (Test-Path -LiteralPath $records -PathType Container)) { return @() }
  return @(Get-ChildItem -LiteralPath $records -Filter '*.json' -File | ForEach-Object {
    try { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json -ErrorAction Stop } catch { }
  })
}

function Restore-RabbitDlpQuarantineFile {
  param(
    [Parameter(Mandatory = $true)][string] $QuarantineId,
    [Parameter(Mandatory = $true)][string] $DataRoot
  )
  if ($QuarantineId -notmatch '^[0-9a-f]{32}$') { throw 'El ID de cuarentena no es válido.' }
  $root = Join-Path $DataRoot 'quarantine'
  $objectPath = Join-Path $root ('objects\' + $QuarantineId + '.bin')
  $recordPath = Join-Path $root ('records\' + $QuarantineId + '.json')
  if (-not (Test-Path -LiteralPath $objectPath -PathType Leaf) -or -not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
    throw 'No existe el archivo o el registro de cuarentena solicitado.'
  }
  $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json -ErrorAction Stop
  if ($record.id -ne $QuarantineId -or $record.state -notin @('pending-delete', 'quarantined') -or
      $record.sha256 -notmatch '^[0-9a-f]{64}$' -or -not [IO.Path]::IsPathFullyQualified([string]$record.original_path)) {
    throw 'El registro de cuarentena no es válido.'
  }
  if ((Get-FileHash -LiteralPath $objectPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.sha256) {
    throw 'La copia en cuarentena no coincide con su SHA-256 registrado.'
  }
  $destination = [IO.Path]::GetFullPath([string]$record.original_path)
  $parent = Split-Path -Parent $destination
  if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'La carpeta original no existe; créala antes de restaurar.' }
  if (Test-Path -LiteralPath $destination) { throw 'Ya existe un archivo en la ruta original; no se sobrescribió.' }
  $temporary = Join-Path $parent ('.rabbitdlp-restore-' + $QuarantineId + '.tmp')
  try {
    Copy-Item -LiteralPath $objectPath -Destination $temporary -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.sha256) {
      throw 'La copia restaurada no pasó la verificación SHA-256.'
    }
    if ($record.original_acl_sddl) {
      $acl = Get-Acl -LiteralPath $temporary
      $acl.SetSecurityDescriptorSddlForm([string]$record.original_acl_sddl)
      Set-Acl -LiteralPath $temporary -AclObject $acl
    }
    Move-Item -LiteralPath $temporary -Destination $destination -ErrorAction Stop
    Remove-Item -LiteralPath $objectPath -Force
    Remove-Item -LiteralPath $recordPath -Force
    return $destination
  }
  finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
  }
}
