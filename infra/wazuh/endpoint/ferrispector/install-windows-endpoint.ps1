[CmdletBinding()]
param(
  [Alias('FerrispectorPackage')]
  [string] $RabbitDlpPackage,

  [string] $ExpectedPackageSha256,

  [string] $WazuhManager,

  [ValidatePattern('^[A-Za-z0-9_.,-]{1,255}$')]
  [string] $WazuhAgentGroup = 'default',

  [string] $WazuhAgentName = $env:COMPUTERNAME,

  [string[]] $WatchRoot,

  [string] $DlpControlPlaneUrl,

  [System.Security.SecureString] $RegistrationPassword,

  [string] $SetupConfigPath,

  [string] $ProgressFilePath
)

$script:RabbitDlpSetupMode = [bool]$SetupConfigPath
$script:RabbitDlpConfigPath = $null
$script:RabbitDlpConfigBackupPath = $null
$script:RabbitDlpConfigWasWritten = $false
$script:RabbitDlpLegacyTaskPresent = $false
$script:RabbitDlpLegacyTaskWasRunning = $false
$script:RabbitDlpExistingTaskPresent = $false
$script:RabbitDlpExistingTaskWasRunning = $false
$script:RabbitDlpExistingTaskWasDisabled = $false
$script:RabbitDlpExistingTaskXml = $null
$script:RabbitDlpNewTaskCreated = $false
$script:RabbitDlpReleasePath = $null
$script:RabbitDlpReleaseWasCreated = $false
$script:RabbitDlpDataWasCreated = $false
$script:RabbitDlpWazuhConfigBackupPath = $null
$script:RabbitDlpWazuhConfigWasChanged = $false
$script:RabbitDlpWazuhWasRunning = $false
$script:RabbitDlpEnrollmentCompleted = $false
$script:RabbitDlpCommitted = $false
$script:RabbitDlpSecrets = @()
$script:RabbitDlpCurrentStage = 'Preparando los datos del asistente.'
$script:RabbitDlpMsiLogPath = $null
$script:RabbitDlpEnrollmentStdOutPath = $null
$script:RabbitDlpEnrollmentStdErrPath = $null
$script:RabbitDlpRestoreToolsBackups = @{}
$script:RabbitDlpRestoreToolsCreated = @{}
$temporaryRoot = $null

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-RabbitDlpProgress {
  param(
    [Parameter(Mandatory = $true)][ValidateRange(1, 7)][int] $Step,
    [Parameter(Mandatory = $true)][ValidateRange(0, 100)][int] $Percent,
    [Parameter(Mandatory = $true)][string] $Message
  )
  $script:RabbitDlpCurrentStage = $Message
  if (-not $ProgressFilePath) { return }
  $progressTemp = $ProgressFilePath + '.tmp'
  try {
    [IO.File]::WriteAllText($progressTemp, "$Step|$Percent|$Message", [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $progressTemp -Destination $ProgressFilePath -Force
  }
  catch { }
}

function Write-RabbitDlpFailure {
  param(
    [Parameter(Mandatory = $true)]$Failure,
    [string]$RollbackError
  )

  $message = 'Etapa: ' + $script:RabbitDlpCurrentStage + [Environment]::NewLine + [string]$Failure.Exception.Message
  if ($RollbackError) { $message += [Environment]::NewLine + 'No se pudo revertir completamente: ' + $RollbackError }
  if ($script:RabbitDlpEnrollmentCompleted) {
    $message += [Environment]::NewLine + 'La inscripción remota se completó: revoca el equipo en DLP de endpoints antes de volver a intentarlo.'
  }
  foreach ($secret in $script:RabbitDlpSecrets) {
    if ($secret) { $message = $message.Replace($secret, '[secreto oculto]') }
  }

  $diagnosticDirectory = Join-Path $env:ProgramData 'B89\RabbitDLP\Logs'
  $diagnosticErrorPath = Join-Path $diagnosticDirectory 'install-last-error.txt'
  $diagnosticMsiPath = Join-Path $diagnosticDirectory 'wazuh-agent-install.log'
  try {
    New-Item -ItemType Directory -Path $diagnosticDirectory -Force | Out-Null
    & icacls.exe $diagnosticDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Windows no pudo restringir los permisos de los diagnósticos.' }
    if ($script:RabbitDlpMsiLogPath -and (Test-Path -LiteralPath $script:RabbitDlpMsiLogPath -PathType Leaf)) {
      Copy-Item -LiteralPath $script:RabbitDlpMsiLogPath -Destination $diagnosticMsiPath -Force
      $matches = Get-Content -LiteralPath $script:RabbitDlpMsiLogPath -Tail 1200 |
        Select-String -Pattern '(?i)(error|failed|failure|return value 3|1603|access is denied)' |
        Select-Object -Last 10
      if ($matches) {
        $logExcerpt = @($matches | ForEach-Object { $_.Line })
        foreach ($secret in $script:RabbitDlpSecrets) {
          if ($secret) { $logExcerpt = @($logExcerpt | ForEach-Object { $_.Replace($secret, '[secreto oculto]') }) }
        }
        $message += [Environment]::NewLine + [Environment]::NewLine + 'Líneas relevantes del registro MSI:' +
          [Environment]::NewLine + ($logExcerpt -join [Environment]::NewLine)
      }
      $message += [Environment]::NewLine + [Environment]::NewLine + 'Registro MSI completo: ' + $diagnosticMsiPath
    }
    $enrollmentLogSources = @($script:RabbitDlpEnrollmentStdOutPath, $script:RabbitDlpEnrollmentStdErrPath)
    $enrollmentLogNames = @('wazuh-agent-auth.stdout.log', 'wazuh-agent-auth.stderr.log')
    $enrollmentLines = @()
    for ($index = 0; $index -lt $enrollmentLogSources.Count; $index++) {
      $sourcePath = $enrollmentLogSources[$index]
      if ($sourcePath -and (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        $destinationPath = Join-Path $diagnosticDirectory $enrollmentLogNames[$index]
        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
        $enrollmentLines += Get-Content -LiteralPath $sourcePath -Tail 60
      }
    }
    if ($enrollmentLines.Count -gt 0) {
      foreach ($secret in $script:RabbitDlpSecrets) {
        if ($secret) { $enrollmentLines = @($enrollmentLines | ForEach-Object { ([string]$_).Replace($secret, '[secreto oculto]') }) }
      }
      $message += [Environment]::NewLine + [Environment]::NewLine + 'Salida del registro de Wazuh:' +
        [Environment]::NewLine + ($enrollmentLines -join [Environment]::NewLine)
    }
    if ($script:RabbitDlpCurrentStage -match '(?i)wazuh|agente') {
      $wazuhLogPath = 'C:\Program Files (x86)\ossec-agent\ossec.log'
      if (Test-Path -LiteralPath $wazuhLogPath -PathType Leaf) {
        try {
          $wazuhMatches = Get-Content -LiteralPath $wazuhLogPath -Tail 400 -ErrorAction Stop |
            Select-String -Pattern '(?i)(authd|invalid password|no authentication password|requesting a key|waiting for server reply|unable to add agent|authentication error|connected to|error|failed)' |
            Select-Object -Last 12
          if ($wazuhMatches) {
            $wazuhExcerpt = @($wazuhMatches | ForEach-Object { $_.Line })
            foreach ($secret in $script:RabbitDlpSecrets) {
              if ($secret) { $wazuhExcerpt = @($wazuhExcerpt | ForEach-Object { $_.Replace($secret, '[secreto oculto]') }) }
            }
            $message += [Environment]::NewLine + [Environment]::NewLine + 'Líneas relevantes del registro del agente Wazuh:' +
              [Environment]::NewLine + ($wazuhExcerpt -join [Environment]::NewLine)
          }
        }
        catch { }
      }
      $message += [Environment]::NewLine + 'Registro del agente Wazuh: ' + $wazuhLogPath
    }
    $message += [Environment]::NewLine + 'Diagnóstico: ' + $diagnosticErrorPath
    [IO.File]::WriteAllText($diagnosticErrorPath, $message, [Text.UTF8Encoding]::new($false))
  }
  catch {
    $message += [Environment]::NewLine + 'No se pudo guardar el diagnóstico persistente: ' + $_.Exception.Message
  }

  if ($ProgressFilePath) {
    try {
      [IO.File]::WriteAllText(($ProgressFilePath + '.error'), $message, [Text.UTF8Encoding]::new($false))
    }
    catch { }
  }
}

try {
if ($SetupConfigPath) {
  if (-not (Test-Path -LiteralPath $SetupConfigPath -PathType Leaf)) { throw 'RabbitDLP setup data is missing.' }
  $setup = Get-Content -LiteralPath $SetupConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop
  $FerrispectorPackage = [string]$setup.packagePath
  $ExpectedPackageSha256 = [string]$setup.packageSha256
  $WazuhManager = [string]$setup.wazuhManager
  $WazuhAgentGroup = [string]$setup.wazuhAgentGroup
  $WazuhAgentName = if ([string]::IsNullOrWhiteSpace([string]$setup.wazuhAgentName)) { $env:COMPUTERNAME } else { [string]$setup.wazuhAgentName }
  $WatchRoot = @($setup.watchRoots | ForEach-Object { [string]$_ })
  $DlpControlPlaneUrl = [string]$setup.dlpControlPlaneUrl
  $DlpEnrollmentToken = [string]$setup.dlpEnrollmentToken
  if ($DlpEnrollmentToken) { $script:RabbitDlpSecrets += $DlpEnrollmentToken }
  if ($setup.wazuhRegistrationPassword) {
    $script:RabbitDlpSecrets += [string]$setup.wazuhRegistrationPassword
    $RegistrationPassword = ConvertTo-SecureString -String ([string]$setup.wazuhRegistrationPassword) -AsPlainText -Force
  }
  Remove-Item -LiteralPath $SetupConfigPath -Force
  $setup = $null
}

$oldDiagnosticDirectory = Join-Path $env:ProgramData 'B89\RabbitDLP\Logs'
Remove-Item -LiteralPath (Join-Path $oldDiagnosticDirectory 'install-last-error.txt') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $oldDiagnosticDirectory 'wazuh-agent-install.log') -Force -ErrorAction SilentlyContinue

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

function Test-WindowsCloudFilesDirectory {
  param([Parameter(Mandatory = $true)][string]$Path)

  $fsutilPath = Join-Path $env:SystemRoot 'System32\fsutil.exe'
  if (-not (Test-Path -LiteralPath $fsutilPath -PathType Leaf)) { return $false }
  $reparseOutput = & $fsutilPath reparsepoint query $Path 2>$null
  if ($LASTEXITCODE -ne 0) { return $false }
  $tagMatches = [regex]::Matches(($reparseOutput -join [Environment]::NewLine), '(?i)0x[0-9a-f]{8}')
  foreach ($tagMatch in $tagMatches) {
    if ($tagMatch.Value -match '(?i)^0x9000[0-9a-f]01a$') { return $true }
  }
  return $false
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

function Set-WazuhRegistrationPassword {
  param([Parameter(Mandatory = $true)][string]$AgentHome)

  $passwordPath = Join-Path $AgentHome 'authd.pass'
  if (-not $RegistrationPassword) {
    if (Test-Path -LiteralPath $passwordPath -PathType Leaf) { return }
    throw 'El agente Wazuh aún no está registrado y no hay una contraseña authd.pass guardada. Vuelve a ejecutar RabbitDLP e introduce la contraseña de registro de Wazuh.'
  }
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($RegistrationPassword)
  try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [IO.File]::WriteAllText($passwordPath, $plainPassword, [Text.Encoding]::ASCII)
    Set-PrivateAcl -Path $passwordPath
  }
  finally {
    if ($plainPassword) { $plainPassword = $null }
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }
}

function Wait-WazuhEnrollment {
  param([Parameter(Mandatory = $true)][string]$AgentHome)

  $clientKeyPath = Join-Path $AgentHome 'client.keys'
  $enrollmentDeadline = [DateTime]::UtcNow.AddSeconds(60)
  while (-not (Test-Path -LiteralPath $clientKeyPath -PathType Leaf) -and [DateTime]::UtcNow -lt $enrollmentDeadline) {
    Start-Sleep -Seconds 2
    $agentService = Get-Service -Name 'WazuhSvc' -ErrorAction Stop
    if ($agentService.Status -ne 'Running') {
      throw 'El servicio Wazuh se detuvo durante el registro del agente.'
    }
  }
  if (-not (Test-Path -LiteralPath $clientKeyPath -PathType Leaf) -or (Get-Item -LiteralPath $clientKeyPath).Length -eq 0) {
    throw 'Wazuh no registró el agente en 60 segundos. Comprueba que el administrador público acepte TCP 1515 (registro) y TCP 1514 (datos), que authd esté habilitado, que la contraseña coincida y que el grupo seleccionado exista en Wazuh. El detalle del agente está en C:\Program Files (x86)\ossec-agent\ossec.log.'
  }
}

function Invoke-WazuhAgentEnrollment {
  param(
    [Parameter(Mandatory = $true)][string]$AgentHome,
    [Parameter(Mandatory = $true)][string]$AgentManager
  )

  $agentAuthPath = Join-Path $AgentHome 'agent-auth.exe'
  if (-not (Test-Path -LiteralPath $agentAuthPath -PathType Leaf)) {
    throw 'No se encontró agent-auth.exe en el paquete de Wazuh; no se puede registrar el agente.'
  }
  if (-not $temporaryRoot -or -not (Test-Path -LiteralPath $temporaryRoot -PathType Container)) {
    throw 'No existe el directorio temporal protegido para registrar Wazuh.'
  }
  $script:RabbitDlpEnrollmentStdOutPath = Join-Path $temporaryRoot 'wazuh-agent-auth.stdout.log'
  $script:RabbitDlpEnrollmentStdErrPath = Join-Path $temporaryRoot 'wazuh-agent-auth.stderr.log'
  $arguments = @('-m', $AgentManager, '-A', $WazuhAgentName, '-G', $WazuhAgentGroup) -join ' '
  $process = Start-Process -FilePath $agentAuthPath -ArgumentList $arguments -WorkingDirectory $AgentHome -RedirectStandardOutput $script:RabbitDlpEnrollmentStdOutPath -RedirectStandardError $script:RabbitDlpEnrollmentStdErrPath -PassThru -WindowStyle Hidden
  if (-not $process.WaitForExit(60000)) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    throw 'El registro directo de Wazuh agotó el tiempo de espera de 60 segundos. Consulta la conectividad y la salida de agent-auth.'
  }
  $process.Refresh()
  if ($process.ExitCode -ne 0) {
    throw "agent-auth.exe terminó con código $($process.ExitCode). Revisa si el grupo existe, si la contraseña coincide y si TCP 1515 está accesible."
  }
  $clientKeyPath = Join-Path $AgentHome 'client.keys'
  if (-not (Test-Path -LiteralPath $clientKeyPath -PathType Leaf) -or (Get-Item -LiteralPath $clientKeyPath).Length -eq 0) {
    throw 'agent-auth.exe terminó correctamente, pero no creó una clave Wazuh local. Revisa la salida de agent-auth y el ossec.log del agente.'
  }
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
    $agentHome = 'C:\Program Files (x86)\ossec-agent'
    $clientKeyPath = Join-Path $agentHome 'client.keys'
    if (-not (Test-Path -LiteralPath $clientKeyPath -PathType Leaf) -or (Get-Item -LiteralPath $clientKeyPath).Length -eq 0) {
      Write-RabbitDlpProgress -Step 2 -Percent 22 -Message 'Reintentando el registro pendiente del agente Wazuh.'
      $wasRunning = $agentService.Status -eq 'Running'
      if ($wasRunning) { Stop-Service -Name 'WazuhSvc' -Force }
      try {
        Set-WazuhRegistrationPassword -AgentHome $agentHome
        Invoke-WazuhAgentEnrollment -AgentHome $agentHome -AgentManager $AgentManager
      }
      catch {
        if ($wasRunning) { Start-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue }
        throw
      }
      Set-Service -Name 'WazuhSvc' -StartupType Automatic
      Start-Service -Name 'WazuhSvc'
      Wait-WazuhEnrollment -AgentHome $agentHome
    }
    else {
      Write-RabbitDlpProgress -Step 2 -Percent 22 -Message 'Agente Wazuh existente: comprobando la conexión.'
    }
    return
  }

  if (-not $RegistrationPassword -and $script:RabbitDlpSetupMode) {
    throw 'Wazuh is not installed; rerun RabbitDLP setup with its Wazuh registration password.'
  }
  if (-not $RegistrationPassword) {
    $script:RegistrationPassword = Read-Host 'Wazuh enrollment password' -AsSecureString
  }
  if (-not $script:RegistrationPassword -or $script:RegistrationPassword.Length -eq 0) {
    throw 'A Wazuh enrollment password is required when installing a new Wazuh agent.'
  }

  $version = '4.14.11'
  Write-RabbitDlpProgress -Step 2 -Percent 18 -Message 'Descargando el instalador oficial de Wazuh.'
  $msiPath = Join-Path ([IO.Path]::GetTempPath()) ("wazuh-agent-$version-1-$([guid]::NewGuid().ToString('N')).msi")
  $msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$version-1.msi"
  $script:RabbitDlpMsiLogPath = $msiPath + '.log'
  try {
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath
    Write-RabbitDlpProgress -Step 2 -Percent 21 -Message 'Verificando la firma digital de Wazuh.'
    $signature = Get-AuthenticodeSignature -LiteralPath $msiPath
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
      throw "Wazuh MSI signature is not valid ($($signature.Status))."
    }
    $publisher = $signature.SignerCertificate.GetNameInfo(
      [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
      $false
    )
    if (($publisher -replace '[^A-Za-z0-9]', '').ToLowerInvariant() -cne 'wazuhinc') {
      throw "Wazuh MSI signer is '$publisher'; expected 'Wazuh, Inc'."
    }
    $arguments = @(
      '/i', ('"' + $msiPath + '"'), '/qn', '/norestart', '/l*v', ('"' + $script:RabbitDlpMsiLogPath + '"'),
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
  $agentHome = 'C:\Program Files (x86)\ossec-agent'
  $wasRunning = $agentService.Status -eq 'Running'
  if ($wasRunning) { Stop-Service -Name 'WazuhSvc' -Force }
  Set-Service -Name 'WazuhSvc' -StartupType Automatic
  Write-RabbitDlpProgress -Step 2 -Percent 24 -Message 'Conectando el agente Wazuh con el administrador.'
  try {
    Set-WazuhRegistrationPassword -AgentHome $agentHome
    if (-not (Test-Path -LiteralPath (Join-Path $agentHome 'client.keys') -PathType Leaf) -or
        (Get-Item -LiteralPath (Join-Path $agentHome 'client.keys') -ErrorAction SilentlyContinue).Length -eq 0) {
      Invoke-WazuhAgentEnrollment -AgentHome $agentHome -AgentManager $AgentManager
    }
  }
  catch {
    if ($wasRunning) { Start-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue }
    throw
  }
  Start-Service -Name 'WazuhSvc'
  Wait-WazuhEnrollment -AgentHome $agentHome
  Write-Output "Installed Wazuh agent $version for $AgentManager in group $WazuhAgentGroup."
}

Assert-Administrator
if ($WazuhManager -notmatch '^[A-Za-z0-9.-]{1,253}$') { throw 'WazuhManager must be a host name or IPv4 address.' }
if ($ExpectedPackageSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'The embedded RabbitDLP package SHA-256 is invalid.' }
if (-not $FerrispectorPackage) { throw 'The RabbitDLP package path is missing.' }
Write-RabbitDlpProgress -Step 1 -Percent 5 -Message 'Verificando el paquete y la arquitectura de Windows.'
if ($WazuhAgentName -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw 'WazuhAgentName contains unsupported characters.' }
if (-not $WatchRoot -or $WatchRoot.Count -eq 0) { throw 'Supply at least one explicitly approved local WatchRoot; the installer chooses no directories.' }
foreach ($root in $WatchRoot) {
  if ($root.StartsWith('\\') -or -not [IO.Path]::IsPathRooted($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "WatchRoot must be an existing local directory: $root"
  }
  $rootItem = Get-Item -LiteralPath $root -Force
  if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -and
      -not (Test-WindowsCloudFilesDirectory -Path $root)) {
    throw "La carpeta seleccionada es un enlace o punto de reanálisis no compatible: $root. Selecciona una carpeta normal o una carpeta local de Cloud Files."
  }
}

$packagePath = [IO.Path]::GetFullPath($RabbitDlpPackage)
if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) { throw 'Ferrispector package zip was not found.' }
$packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($packageHash -ne $ExpectedPackageSha256.ToLowerInvariant()) { throw 'Ferrispector package SHA-256 does not match the independently supplied expected hash.' }
$architecture = Get-WindowsArchitecture
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("b89-ferrispector-install-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
  Expand-Archive -LiteralPath $packagePath -DestinationPath $temporaryRoot
  $manifestPath = Join-Path $temporaryRoot 'manifest.json'
  if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Ferrispector package is missing manifest.json.' }
  $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
  if ($manifest.product -notin @('RabbitDLP', 'B89 Ferrispector') -or $manifest.engine -ne 'YARA-X CLI' -or
      $manifest.engineVersion -ne '1.24.0' -or $manifest.architecture -ne $architecture) {
    throw 'Ferrispector package identity, pinned YARA-X version, or architecture does not match this endpoint.'
  }
  if ($manifest.installMode -ne 'detection, exact-fingerprint quarantine and optional Defender device control; monitored roots are operator supplied') {
    throw 'RabbitDLP package install mode is not recognized.'
  }
  $sourceEngine = Join-Path $temporaryRoot 'bin\yr.exe'
  $sourceRules = Join-Path $temporaryRoot 'policy\dlp-rules.yarc'
  $sourceFingerprints = Join-Path $temporaryRoot 'policy\fingerprints.sha256'
  if (-not (Test-Path -LiteralPath $sourceEngine -PathType Leaf) -or -not (Test-Path -LiteralPath $sourceRules -PathType Leaf) -or
      -not (Test-Path -LiteralPath $sourceFingerprints -PathType Leaf)) {
    throw 'Ferrispector package must contain YARA-X, its DLP rules and a SHA-256 fingerprint catalog.'
  }
  foreach ($requiredScript in @('rabbitdlp-device-control.ps1', 'rabbitdlp-quarantine.ps1', 'restore-quarantined-file.ps1')) {
    if (-not (Test-Path -LiteralPath (Join-Path $temporaryRoot $requiredScript) -PathType Leaf)) {
      throw "RabbitDLP package is missing $requiredScript. Build a current signed-off package."
    }
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
  Write-RabbitDlpProgress -Step 2 -Percent 14 -Message 'Preparando el agente Wazuh del equipo.'
  Install-WazuhAgentIfMissing -AgentManager $WazuhManager

  # Bind installation identity to the entire verified package so a wrapper,
  # installer, notice, or policy change always creates a distinct release.
  $releaseId = "yara-x-$($manifest.engineVersion)-$architecture-$($packageHash.Substring(0, 16))"
  $installRoot = Join-Path $env:ProgramFiles 'B89\RabbitDLP'
  $releasesRoot = Join-Path $installRoot 'releases'
  $releasePath = Join-Path $releasesRoot $releaseId
  $script:RabbitDlpReleasePath = $releasePath
  New-Item -ItemType Directory -Path $releasesRoot -Force | Out-Null
  if (-not (Test-Path -LiteralPath (Join-Path $releasePath 'manifest.json'))) {
    Write-RabbitDlpProgress -Step 3 -Percent 36 -Message 'Instalando el motor de detección y las reglas aprobadas.'
    $stagePath = Join-Path $releasesRoot ($releaseId + '.staging')
    if (Test-Path -LiteralPath $stagePath) { Remove-Item -LiteralPath $stagePath -Recurse -Force }
    New-Item -ItemType Directory -Path $stagePath -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $temporaryRoot 'bin') -Destination $stagePath -Recurse
    Copy-Item -LiteralPath (Join-Path $temporaryRoot 'policy') -Destination $stagePath -Recurse
    Copy-Item -LiteralPath (Join-Path $temporaryRoot 'ferrispector.ps1') -Destination $stagePath
    Copy-Item -LiteralPath (Join-Path $temporaryRoot 'rabbitdlp-device-control.ps1') -Destination $stagePath
    Copy-Item -LiteralPath (Join-Path $temporaryRoot 'rabbitdlp-quarantine.ps1') -Destination $stagePath
    Copy-Item -LiteralPath (Join-Path $temporaryRoot 'restore-quarantined-file.ps1') -Destination $stagePath
    Copy-Item -LiteralPath $notices -Destination $stagePath
    Copy-Item -LiteralPath $manifestPath -Destination $stagePath
    Move-Item -LiteralPath $stagePath -Destination $releasePath
    $script:RabbitDlpReleaseWasCreated = $true
  }

  $dataRoot = Join-Path $env:ProgramData 'B89\Ferrispector'
  $script:RabbitDlpDataWasCreated = -not (Test-Path -LiteralPath $dataRoot)
  New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
  Set-PrivateAcl -Path $dataRoot
  $eventsPath = Join-Path $dataRoot 'events.jsonl'
  if (-not (Test-Path -LiteralPath $eventsPath)) { [IO.File]::WriteAllText($eventsPath, '', [Text.UTF8Encoding]::new($false)) }
  $configPath = Join-Path $dataRoot 'config.json'
  $config = [ordered]@{
    schema_version = 2
    rules_path = (Join-Path $releasePath 'policy\dlp-rules.yarc')
    fingerprints_path = (Join-Path $releasePath 'policy\fingerprints.sha256')
    events_path = $eventsPath
    watch_roots = @($WatchRoot | ForEach-Object { [IO.Path]::GetFullPath($_) })
    include_subdirectories = $true
    reconcile_interval_minutes = 60
  }
  if ($DlpControlPlaneUrl) {
    Write-RabbitDlpProgress -Step 4 -Percent 52 -Message 'Inscribiendo el equipo en DLP de B89.'
    $controlPlane = [Uri]$DlpControlPlaneUrl
    if ($controlPlane.Scheme -ne 'https' -or $controlPlane.UserInfo -or $controlPlane.Query -or $controlPlane.Fragment) {
      throw 'DlpControlPlaneUrl must be an HTTPS origin or base path without credentials, query or fragment.'
    }
    if ($DlpEnrollmentToken) {
      $secureToken = ConvertTo-SecureString -String $DlpEnrollmentToken -AsPlainText -Force
      $DlpEnrollmentToken = $null
    }
    else {
      $secureToken = Read-Host 'Token de inscripción de DLP (se usa una vez para inscribir este equipo)' -AsSecureString
    }
    $tokenBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try {
      $enrollmentToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenBstr)
      if (-not $enrollmentToken) { throw 'A DLP enrollment token is required when a control plane is configured.' }
      $agentId = [guid]::NewGuid().ToString('N').Substring(0, 16)
      $enrollmentUri = $controlPlane.AbsoluteUri.TrimEnd('/') + '/api/dlp/agent/enroll'
      $enrollment = Invoke-RestMethod -Method Post -Uri $enrollmentUri -Headers @{ Authorization = "Bearer $enrollmentToken" } `
        -ContentType 'application/json' -Body (@{ hostname = $env:COMPUTERNAME; agentId = $agentId } | ConvertTo-Json -Compress) -TimeoutSec 20
      if (-not $enrollment.endpointId -or $enrollment.endpointCredential -notmatch '^[A-Za-z0-9_-]{40,64}$') { throw 'The DLP control plane did not return a new endpoint credential. Revoke the endpoint and create a fresh enrollment token.' }
      $script:RabbitDlpEnrollmentCompleted = $true
      $config.control_plane_url = $controlPlane.AbsoluteUri.TrimEnd('/')
      $config.agent_credential = [string]$enrollment.endpointCredential
      $config.agent_id = $agentId
      Write-RabbitDlpProgress -Step 4 -Percent 68 -Message 'Inscripción completada; guardando la credencial protegida.'
    }
    finally {
      $enrollmentToken = $null
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenBstr)
      $secureToken.Dispose()
    }
  }
  $script:RabbitDlpConfigPath = $configPath
  if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    $script:RabbitDlpConfigBackupPath = $configPath + '.rabbitdlp-' + [guid]::NewGuid().ToString('N') + '.bak'
    Copy-Item -LiteralPath $configPath -Destination $script:RabbitDlpConfigBackupPath
    Set-PrivateAcl -Path $script:RabbitDlpConfigBackupPath
  }
  $legacyTask = Get-ScheduledTask -TaskName 'B89 Ferrispector' -ErrorAction SilentlyContinue
  $script:RabbitDlpLegacyTaskPresent = [bool]$legacyTask
  if ($legacyTask -and $legacyTask.State -eq 'Running') {
    $script:RabbitDlpLegacyTaskWasRunning = $true
    Stop-ScheduledTask -TaskName 'B89 Ferrispector'
    $legacyDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
      Start-Sleep -Milliseconds 250
      $legacyState = (Get-ScheduledTask -TaskName 'B89 Ferrispector' -ErrorAction Stop).State
    } while ($legacyState -eq 'Running' -and [DateTime]::UtcNow -lt $legacyDeadline)
    if ($legacyState -eq 'Running') { throw 'The previous Ferrispector task did not stop; RabbitDLP left it unchanged.' }
  }
  $existingRabbitTask = Get-ScheduledTask -TaskName 'RabbitDLP' -ErrorAction SilentlyContinue
  if ($existingRabbitTask) {
    $script:RabbitDlpExistingTaskPresent = $true
    $script:RabbitDlpExistingTaskWasRunning = $existingRabbitTask.State -eq 'Running'
    $script:RabbitDlpExistingTaskWasDisabled = $existingRabbitTask.State -eq 'Disabled'
    $script:RabbitDlpExistingTaskXml = Export-ScheduledTask -TaskName 'RabbitDLP' -ErrorAction Stop
    if ($script:RabbitDlpExistingTaskWasRunning) {
      Stop-ScheduledTask -TaskName 'RabbitDLP'
      $existingDeadline = [DateTime]::UtcNow.AddSeconds(15)
      do {
        Start-Sleep -Milliseconds 250
        $existingState = (Get-ScheduledTask -TaskName 'RabbitDLP' -ErrorAction Stop).State
      } while ($existingState -eq 'Running' -and [DateTime]::UtcNow -lt $existingDeadline)
      if ($existingState -eq 'Running') { throw 'The existing RabbitDLP task did not stop; no installation changes were applied.' }
    }
  }
  $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding utf8
  $script:RabbitDlpConfigWasWritten = $true
  Set-PrivateAcl -Path $configPath
  if ($config.agent_credential) { $config.agent_credential = $null }
  $enrollment = $null

  $powerShell = (Get-Process -Id $PID).Path
  $runnerPath = Join-Path $releasePath 'ferrispector.ps1'
  $taskArguments = "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File `"$runnerPath`" -Mode Watch -ConfigPath `"$configPath`""
  $action = New-ScheduledTaskAction -Execute $powerShell -Argument $taskArguments
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
  Write-RabbitDlpProgress -Step 5 -Percent 78 -Message 'Registrando el servicio RabbitDLP para iniciar con Windows.'
  Register-ScheduledTask -TaskName 'RabbitDLP' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Monitorea las carpetas aprobadas; gestiona cuarentena de huellas exactas y control USB opcional.' -Force | Out-Null
  $script:RabbitDlpNewTaskCreated = $true
  Write-RabbitDlpProgress -Step 5 -Percent 88 -Message 'Vinculando los eventos JSON con el agente Wazuh.'
  $agentConfigPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
  $script:RabbitDlpWazuhConfigBackupPath = Join-Path $dataRoot ('ossec.conf.' + [guid]::NewGuid().ToString('N') + '.bak')
  Copy-Item -LiteralPath $agentConfigPath -Destination $script:RabbitDlpWazuhConfigBackupPath
  $wazuhService = Get-Service -Name 'WazuhSvc' -ErrorAction Stop
  $script:RabbitDlpWazuhWasRunning = $wazuhService.Status -eq 'Running'
  $wazuhConfigChanged = Add-WazuhFerrispectorLocalfile
  $script:RabbitDlpWazuhConfigWasChanged = $wazuhConfigChanged
  if ($wazuhConfigChanged -and $wazuhService.Status -eq 'Running') { Restart-Service -Name 'WazuhSvc' -Force }
  elseif ($wazuhService.Status -ne 'Running') { Start-Service -Name 'WazuhSvc' }
  Write-RabbitDlpProgress -Step 6 -Percent 94 -Message 'Iniciando RabbitDLP y comprobando la tarea programada.'
  Start-ScheduledTask -TaskName 'RabbitDLP'
  $deadline = [DateTime]::UtcNow.AddSeconds(15)
  do {
    Start-Sleep -Milliseconds 500
    $taskState = (Get-ScheduledTask -TaskName 'RabbitDLP' -ErrorAction Stop).State
  } while ($taskState -ne 'Running' -and [DateTime]::UtcNow -lt $deadline)
  if ($taskState -ne 'Running') {
    $taskInfo = Get-ScheduledTaskInfo -TaskName 'RabbitDLP' -ErrorAction Stop
    throw "RabbitDLP failed to start (task result $($taskInfo.LastTaskResult))."
  }
  if ($script:RabbitDlpLegacyTaskPresent) { Unregister-ScheduledTask -TaskName 'B89 Ferrispector' -Confirm:$false }
  $restoreToolsRoot = Join-Path $env:ProgramData 'B89\RabbitDLP'
  New-Item -ItemType Directory -Path $restoreToolsRoot -Force | Out-Null
  Set-PrivateAcl -Path $restoreToolsRoot
  foreach ($utilityName in @('rabbitdlp-device-control.ps1', 'rabbitdlp-quarantine.ps1', 'restore-quarantined-file.ps1')) {
    $utilityDestination = Join-Path $restoreToolsRoot $utilityName
    if (Test-Path -LiteralPath $utilityDestination -PathType Leaf) {
      $utilityBackup = Join-Path $temporaryRoot ($utilityName + '.backup')
      Copy-Item -LiteralPath $utilityDestination -Destination $utilityBackup -Force
      $script:RabbitDlpRestoreToolsBackups[$utilityDestination] = $utilityBackup
    } else { $script:RabbitDlpRestoreToolsCreated[$utilityDestination] = $true }
    Copy-Item -LiteralPath (Join-Path $releasePath $utilityName) -Destination $utilityDestination -Force
    Set-PrivateAcl -Path $utilityDestination
  }
  $script:RabbitDlpCommitted = $true
  if ($script:RabbitDlpConfigBackupPath -and (Test-Path -LiteralPath $script:RabbitDlpConfigBackupPath)) {
    Remove-Item -LiteralPath $script:RabbitDlpConfigBackupPath -Force -ErrorAction SilentlyContinue
  }
  if ($script:RabbitDlpWazuhConfigBackupPath -and (Test-Path -LiteralPath $script:RabbitDlpWazuhConfigBackupPath)) {
    Remove-Item -LiteralPath $script:RabbitDlpWazuhConfigBackupPath -Force -ErrorAction SilentlyContinue
  }
  $oldInstallRoot = Join-Path $env:ProgramFiles 'B89\Ferrispector'
  if (Test-Path -LiteralPath $oldInstallRoot) { Remove-Item -LiteralPath $oldInstallRoot -Recurse -Force -ErrorAction SilentlyContinue }
  Write-RabbitDlpProgress -Step 7 -Percent 100 -Message 'RabbitDLP está instalado y conectado.'
}
catch {
  $failureRecord = $_
  $rollbackError = $null
  if (-not $script:RabbitDlpCommitted) {
    try {
    if ($script:RabbitDlpExistingTaskPresent -and $script:RabbitDlpExistingTaskXml) {
      Stop-ScheduledTask -TaskName 'RabbitDLP' -ErrorAction SilentlyContinue
      Register-ScheduledTask -TaskName 'RabbitDLP' -Xml $script:RabbitDlpExistingTaskXml -Force -ErrorAction SilentlyContinue | Out-Null
      if ($script:RabbitDlpExistingTaskWasDisabled) { Disable-ScheduledTask -TaskName 'RabbitDLP' -ErrorAction SilentlyContinue }
      elseif ($script:RabbitDlpExistingTaskWasRunning) { Start-ScheduledTask -TaskName 'RabbitDLP' -ErrorAction SilentlyContinue }
    }
    elseif ($script:RabbitDlpNewTaskCreated) {
      Stop-ScheduledTask -TaskName 'RabbitDLP' -ErrorAction SilentlyContinue
      Unregister-ScheduledTask -TaskName 'RabbitDLP' -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($script:RabbitDlpConfigWasWritten -and $script:RabbitDlpConfigPath) {
      if ($script:RabbitDlpConfigBackupPath -and (Test-Path -LiteralPath $script:RabbitDlpConfigBackupPath)) {
        Copy-Item -LiteralPath $script:RabbitDlpConfigBackupPath -Destination $script:RabbitDlpConfigPath -Force
        Set-PrivateAcl -Path $script:RabbitDlpConfigPath
      }
      else {
        Remove-Item -LiteralPath $script:RabbitDlpConfigPath -Force -ErrorAction SilentlyContinue
      }
    }
    if ($script:RabbitDlpConfigBackupPath) {
      Remove-Item -LiteralPath $script:RabbitDlpConfigBackupPath -Force -ErrorAction SilentlyContinue
    }
    if ($script:RabbitDlpWazuhConfigBackupPath -and (Test-Path -LiteralPath $script:RabbitDlpWazuhConfigBackupPath)) {
      Copy-Item -LiteralPath $script:RabbitDlpWazuhConfigBackupPath -Destination 'C:\Program Files (x86)\ossec-agent\ossec.conf' -Force
      if ($script:RabbitDlpWazuhConfigWasChanged) {
        $serviceAfterRollback = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
        if ($script:RabbitDlpWazuhWasRunning -and $serviceAfterRollback -and $serviceAfterRollback.Status -eq 'Running') {
          Restart-Service -Name 'WazuhSvc' -Force -ErrorAction SilentlyContinue
        }
        elseif (-not $script:RabbitDlpWazuhWasRunning -and $serviceAfterRollback -and $serviceAfterRollback.Status -eq 'Running') {
          Stop-Service -Name 'WazuhSvc' -Force -ErrorAction SilentlyContinue
        }
      }
    }
    if ($script:RabbitDlpWazuhConfigBackupPath) {
      Remove-Item -LiteralPath $script:RabbitDlpWazuhConfigBackupPath -Force -ErrorAction SilentlyContinue
    }
    foreach ($utilityDestination in $script:RabbitDlpRestoreToolsBackups.Keys) {
      $utilityBackup = $script:RabbitDlpRestoreToolsBackups[$utilityDestination]
      if (Test-Path -LiteralPath $utilityBackup -PathType Leaf) {
        Copy-Item -LiteralPath $utilityBackup -Destination $utilityDestination -Force
        Set-PrivateAcl -Path $utilityDestination
      }
    }
    foreach ($utilityDestination in $script:RabbitDlpRestoreToolsCreated.Keys) {
      Remove-Item -LiteralPath $utilityDestination -Force -ErrorAction SilentlyContinue
    }
    if ($script:RabbitDlpLegacyTaskPresent -and $script:RabbitDlpLegacyTaskWasRunning) {
      Start-ScheduledTask -TaskName 'B89 Ferrispector' -ErrorAction SilentlyContinue
    }
    if ($script:RabbitDlpReleaseWasCreated -and $script:RabbitDlpReleasePath -and
        (Test-Path -LiteralPath $script:RabbitDlpReleasePath)) {
      Remove-Item -LiteralPath $script:RabbitDlpReleasePath -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($script:RabbitDlpDataWasCreated -and $dataRoot -and (Test-Path -LiteralPath $dataRoot)) {
      Remove-Item -LiteralPath $dataRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    }
    catch { $rollbackError = $_.Exception.Message }
  }
  Write-RabbitDlpFailure -Failure $failureRecord -RollbackError $rollbackError
  throw $failureRecord
}
finally {
  if ($temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
  if ($script:RabbitDlpCommitted -and $script:RabbitDlpMsiLogPath -and (Test-Path -LiteralPath $script:RabbitDlpMsiLogPath)) {
    Remove-Item -LiteralPath $script:RabbitDlpMsiLogPath -Force -ErrorAction SilentlyContinue
  }
}
