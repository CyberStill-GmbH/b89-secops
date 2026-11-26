#ifndef AppVersion
  #define AppVersion "1.1.0"
#endif
#ifndef Architecture
  #define Architecture "x64"
#endif
#ifndef PayloadPath
  #error PayloadPath must identify the built Windows payload ZIP.
#endif
#ifndef PayloadSha256
  #error PayloadSha256 must contain the verified SHA-256 of the payload ZIP.
#endif
#ifndef OutputDirectory
  #define OutputDirectory "..\..\..\..\dist\rabbitdlp"
#endif

#define ProductName "RabbitDLP"
#define PublisherName "B89"
#define PayloadName ExtractFileName(PayloadPath)
#if Architecture == "x64"
  #define AllowedArchitectures "x64os"
  #define InstallArchitecture "x64os"
#elif Architecture == "arm64"
  #define AllowedArchitectures "arm64"
  #define InstallArchitecture "arm64"
#else
  #error Architecture must be x64 or arm64.
#endif

[Setup]
AppId={{751C9C57-DA3F-4ED9-8EBE-52A8CB170158}
AppName={#ProductName}
AppVersion={#AppVersion}
AppPublisher={#PublisherName}
DefaultDirName={autopf}\B89\RabbitDLP
DefaultGroupName=RabbitDLP
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed={#AllowedArchitectures}
ArchitecturesInstallIn64BitMode={#InstallArchitecture}
WizardStyle=modern
WizardImageFile=branding\rabbitdlp-wizard.bmp
WizardSmallImageFile=branding\rabbitdlp-wizard-small.bmp
SetupIconFile=branding\rabbitdlp.ico
UninstallDisplayName=RabbitDLP
UninstallDisplayIcon={app}\rabbitdlp.ico
UninstallLogging=yes
Compression=lzma2/ultra64
SolidCompression=yes
OutputDir={#OutputDirectory}
OutputBaseFilename=RabbitDLP-Setup-Windows-{#Architecture}-{#AppVersion}
VersionInfoCompany={#PublisherName}
VersionInfoDescription=Instalador de RabbitDLP para Windows
VersionInfoProductName={#ProductName}
VersionInfoProductVersion={#AppVersion}
VersionInfoTextVersion={#AppVersion}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "{#PayloadPath}"; DestDir: "{tmp}"; Flags: dontcopy noencryption
Source: "install-windows-endpoint.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "branding\rabbitdlp.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "branding\rabbitdlp.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "remove-windows-endpoint.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "README-Windows.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Abrir DLP de endpoints"; Filename: "{code:GetDlpControlPlaneUrl}"; IconFilename: "{app}\rabbitdlp.ico"
Name: "{group}\Desinstalar RabbitDLP"; Filename: "{uninstallexe}"; IconFilename: "{app}\rabbitdlp.ico"

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\remove-windows-endpoint.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "RabbitDLP.RemoveEndpoint"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\releases"

[Run]
Filename: "{code:GetDlpControlPlaneUrl}"; Description: "Abrir DLP de endpoints de B89"; Flags: postinstall shellexec skipifsilent nowait

[Code]
const
  WAIT_OBJECT_0 = 0;
  WAIT_TIMEOUT = $00000102;
  SEE_MASK_NOCLOSEPROCESS = $00000040;

type
  TShellExecuteInfo = record
    cbSize: DWORD;
    fMask: Cardinal;
    Wnd: HWND;
    lpVerb: string;
    lpFile: string;
    lpParameters: string;
    lpDirectory: string;
    nShow: Integer;
    hInstApp: THandle;
    lpIDList: DWORD;
    lpClass: string;
    hkeyClass: THandle;
    dwHotKey: DWORD;
    hMonitor: DWORD;
    hProcess: THandle;
  end;

function ShellExecuteEx(var ExecuteInfo: TShellExecuteInfo): BOOL;
  external 'ShellExecuteExW@shell32.dll stdcall';
function WaitForSingleObject(Handle: THandle; Milliseconds: Cardinal): Cardinal;
  external 'WaitForSingleObject@kernel32.dll stdcall';
function GetExitCodeProcess(Process: THandle; var ExitCode: Cardinal): BOOL;
  external 'GetExitCodeProcess@kernel32.dll stdcall';
function CloseHandle(Handle: THandle): BOOL;
  external 'CloseHandle@kernel32.dll stdcall';

var
  WazuhPage: TInputQueryWizardPage;
  WazuhCredentialsPage: TInputQueryWizardPage;
  DlpPage: TInputQueryWizardPage;
  WatchPage: TWizardPage;
  WatchRoots: TNewListBox;
  WatchRootNote: TNewStaticText;
  AddWatchRootButton: TNewButton;
  RemoveWatchRootButton: TNewButton;
  QueuePage: TOutputProgressWizardPage;
  QueueList: TNewListBox;
  QueueTitles: array[1..7] of String;
  LastQueueStep: Integer;
  SetupProcessRunning: Boolean;
  WazuhAlreadyInstalled: Boolean;
  WazuhAlreadyEnrolled: Boolean;
  SetupSettingsPath: String;
  SetupProgressPath: String;
  SetupErrorPath: String;
  PayloadFilePath: String;

function JsonEscape(const Value: String): String;
var
  I: Integer;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(Value) do begin
    C := Value[I];
    if C = '"' then Result := Result + '\"'
    else if C = '\' then Result := Result + '\\'
    else if C = #13 then Result := Result + '\r'
    else if C = #10 then Result := Result + '\n'
    else if C = #9 then Result := Result + '\t'
    else Result := Result + C;
  end;
end;

function JsonArray(const Values: TStrings): String;
var
  I: Integer;
begin
  Result := '[';
  for I := 0 to Values.Count - 1 do begin
    if I > 0 then Result := Result + ',';
    Result := Result + '"' + JsonEscape(Values[I]) + '"';
  end;
  Result := Result + ']';
end;

function HasOnlyAllowedCharacters(const Value, Allowed: String): Boolean;
var
  I: Integer;
begin
  Result := Length(Value) > 0;
  for I := 1 to Length(Value) do
    if Pos(Value[I], Allowed) = 0 then begin
      Result := False;
      Exit;
    end;
end;

function IsValidManager(const Value: String): Boolean;
var
  I: Integer;
begin
  Result := (Length(Value) > 0) and (Length(Value) <= 253);
  for I := 1 to Length(Value) do
    if Pos(Value[I], 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-') = 0 then begin
      Result := False;
      Exit;
    end;
end;

function GetExistingWazuhManager: String;
var
  Data: AnsiString;
  Configuration: String;
  StartPosition: Integer;
  EndPosition: Integer;
begin
  Result := '';
  if not LoadStringFromFile('C:\Program Files (x86)\ossec-agent\ossec.conf', Data) then Exit;
  Configuration := Utf8Decode(Data);
  StartPosition := Pos('<address>', Configuration);
  if StartPosition = 0 then Exit;
  StartPosition := StartPosition + Length('<address>');
  EndPosition := Pos('</address>', Copy(Configuration, StartPosition, Length(Configuration)));
  if EndPosition = 0 then Exit;
  Result := Trim(Copy(Configuration, StartPosition, EndPosition - 1));
end;

procedure AddWatchRootClick(Sender: TObject);
var
  SelectedDirectory: String;
begin
  SelectedDirectory := '';
  if BrowseForFolder('Selecciona una carpeta local aprobada para vigilar', SelectedDirectory, False) then begin
    if Copy(SelectedDirectory, 1, 2) = '\\' then begin
      MsgBox('RabbitDLP admite carpetas locales. No se pueden elegir rutas de red.', mbError, MB_OK);
      Exit;
    end;
    if WatchRoots.Items.IndexOf(SelectedDirectory) >= 0 then begin
      MsgBox('Esa carpeta ya está en la lista.', mbInformation, MB_OK);
      Exit;
    end;
    WatchRoots.Items.Add(SelectedDirectory);
    WatchRoots.ItemIndex := WatchRoots.Items.Count - 1;
  end;
end;

procedure RemoveWatchRootClick(Sender: TObject);
var
  I: Integer;
begin
  I := WatchRoots.ItemIndex;
  if I >= 0 then WatchRoots.Items.Delete(I);
  if WatchRoots.Items.Count > 0 then WatchRoots.ItemIndex := WatchRoots.Items.Count - 1;
end;

procedure InitializeWizard;
var
  ClientKeyContents: AnsiString;
begin
  WazuhAlreadyInstalled := RegKeyExists(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\WazuhSvc');
  WazuhAlreadyEnrolled := False;
  if WazuhAlreadyInstalled then begin
    WazuhAlreadyEnrolled := LoadStringFromFile('C:\Program Files (x86)\ossec-agent\client.keys', ClientKeyContents) and
      (Length(ClientKeyContents) > 0);
    ClientKeyContents := '';
  end;

  WazuhPage := CreateInputQueryPage(wpWelcome,
    'Conexión con Wazuh', 'RabbitDLP envía sus alertas a un agente Wazuh instalado en este equipo.',
    'Indica el administrador que ya está configurado en Wazuh.');
  WazuhPage.Add('Administrador Wazuh (nombre de host o IP)', False);
  WazuhPage.Add('Grupo Wazuh (debe existir en el administrador)', False);
  WazuhPage.Add('Nombre de este equipo en Wazuh (opcional)', False);
  WazuhPage.Values[1] := 'default';
  if WazuhAlreadyInstalled then WazuhPage.Values[0] := GetExistingWazuhManager;

  WazuhCredentialsPage := CreateInputQueryPage(WazuhPage.ID,
    'Registro de Wazuh', 'Wazuh necesita instalarse o terminar el registro en este equipo.',
    'Introduce la contraseña de registro. Si ya existe authd.pass de un intento anterior, puedes dejarla vacía.');
  WazuhCredentialsPage.Add('Contraseña de registro de Wazuh', True);
  WazuhCredentialsPage.Values[0] := '';

  WatchPage := CreateCustomPage(WazuhCredentialsPage.ID,
    'Carpetas protegidas', 'RabbitDLP solo inspecciona las carpetas que eliges aquí.');
  WatchRootNote := TNewStaticText.Create(WizardForm);
  WatchRootNote.Parent := WatchPage.Surface;
  WatchRootNote.Left := 0;
  WatchRootNote.Top := ScaleY(4);
  WatchRootNote.Width := WatchPage.SurfaceWidth;
  WatchRootNote.Height := ScaleY(34);
  WatchRootNote.Caption := 'Añade carpetas locales aprobadas. Se incluyen sus subcarpetas; el disco completo no se vigila.';

  WatchRoots := TNewListBox.Create(WizardForm);
  WatchRoots.Parent := WatchPage.Surface;
  WatchRoots.Left := 0;
  WatchRoots.Top := ScaleY(42);
  WatchRoots.Width := WatchPage.SurfaceWidth - ScaleX(100);
  WatchRoots.Height := ScaleY(154);
  WatchRoots.TabOrder := 0;

  AddWatchRootButton := TNewButton.Create(WizardForm);
  AddWatchRootButton.Parent := WatchPage.Surface;
  AddWatchRootButton.Left := WatchRoots.Left + WatchRoots.Width + ScaleX(10);
  AddWatchRootButton.Top := WatchRoots.Top;
  AddWatchRootButton.Width := ScaleX(88);
  AddWatchRootButton.Caption := 'Añadir...';
  AddWatchRootButton.OnClick := @AddWatchRootClick;
  AddWatchRootButton.TabOrder := 1;

  RemoveWatchRootButton := TNewButton.Create(WizardForm);
  RemoveWatchRootButton.Parent := WatchPage.Surface;
  RemoveWatchRootButton.Left := AddWatchRootButton.Left;
  RemoveWatchRootButton.Top := AddWatchRootButton.Top + AddWatchRootButton.Height + ScaleY(8);
  RemoveWatchRootButton.Width := AddWatchRootButton.Width;
  RemoveWatchRootButton.Caption := 'Quitar';
  RemoveWatchRootButton.OnClick := @RemoveWatchRootClick;
  RemoveWatchRootButton.TabOrder := 2;

  DlpPage := CreateInputQueryPage(WatchPage.ID,
    'Conectar con B89', 'Usa la clave de un solo uso creada en DLP de endpoints.',
    'Escribe la URL base HTTPS de B89 (por ejemplo, https://servidor), sin una pantalla ni la ruta /api. La clave se consume al inscribir este equipo y no se guarda en RabbitDLP.');
  DlpPage.Add('URL HTTPS de la consola B89', False);
  DlpPage.Add('Clave de inscripción de DLP', True);

  QueuePage := CreateOutputProgressPage('Instalando RabbitDLP', 'Preparando la instalación...');
  QueuePage.SetProgress(0, 100);
  QueueList := TNewListBox.Create(WizardForm);
  QueueList.Parent := QueuePage.Surface;
  QueueList.Left := 0;
  QueueList.Top := ScaleY(60);
  QueueList.Width := QueuePage.SurfaceWidth;
  QueueList.Height := QueuePage.SurfaceHeight - ScaleY(104);
  QueueList.TabOrder := 0;

  QueueTitles[1] := 'Verificar paquete y arquitectura';
  QueueTitles[2] := 'Conectar el agente Wazuh';
  QueueTitles[3] := 'Instalar motor y reglas';
  QueueTitles[4] := 'Inscribir el equipo en DLP de B89';
  QueueTitles[5] := 'Vincular la telemetría con Wazuh';
  QueueTitles[6] := 'Iniciar RabbitDLP en Windows';
  QueueTitles[7] := 'RabbitDLP quedó instalado';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = WazuhCredentialsPage.ID) and WazuhAlreadyEnrolled;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Manager: String;
  GroupName: String;
  Url: String;
begin
  Result := True;
  if CurPageID = WazuhPage.ID then begin
    Manager := Trim(WazuhPage.Values[0]);
    GroupName := Trim(WazuhPage.Values[1]);
    if not IsValidManager(Manager) then begin
      MsgBox('Escribe el nombre de host o la dirección IP del administrador Wazuh.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (Length(GroupName) = 0) or (Length(GroupName) > 255) or
       not HasOnlyAllowedCharacters(GroupName, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.,-') then begin
      MsgBox('El grupo Wazuh debe existir en el administrador y solo puede contener letras, números, punto, coma, guion y guion bajo. Usa default si no tienes un grupo personalizado.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (Trim(WazuhPage.Values[2]) <> '') and
       not HasOnlyAllowedCharacters(Trim(WazuhPage.Values[2]), 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-') then begin
      MsgBox('El nombre del equipo en Wazuh contiene caracteres no admitidos.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;
  if CurPageID = WazuhCredentialsPage.ID then begin
    if not WazuhAlreadyEnrolled and (Length(WazuhCredentialsPage.Values[0]) = 0) and
       not FileExists('C:\Program Files (x86)\ossec-agent\authd.pass') then begin
      MsgBox('Es necesaria la contraseña de registro porque Wazuh aún no ha registrado el agente.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;
  if CurPageID = WatchPage.ID then begin
    if WatchRoots.Items.Count = 0 then begin
      MsgBox('Añade al menos una carpeta local aprobada.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;
  if CurPageID = DlpPage.ID then begin
    Url := Trim(DlpPage.Values[0]);
    if (Copy(Lowercase(Url), 1, 8) <> 'https://') or (Length(Url) <= 8) then begin
      MsgBox('La URL de la consola debe empezar con https://.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if Trim(DlpPage.Values[1]) = '' then begin
      MsgBox('Pega la clave de inscripción de un solo uso.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  I: Integer;
begin
  Result := MemoDirInfo + NewLine + NewLine + 'Conexión de Wazuh:' + NewLine +
    Space + Trim(WazuhPage.Values[0]) + NewLine + NewLine +
    'Carpetas aprobadas:' + NewLine;
  for I := 0 to WatchRoots.Items.Count - 1 do
    Result := Result + Space + WatchRoots.Items[I] + NewLine;
  Result := Result + NewLine + 'Consola de DLP:' + NewLine +
    Space + Trim(DlpPage.Values[0]) + NewLine +
    Space + 'Clave de inscripción: se consume una sola vez y no aparece en este resumen.';
end;

function GetDlpControlPlaneUrl(Param: String): String;
begin
  Result := Trim(DlpPage.Values[0]);
end;

function BuildSetupSettings: String;
var
  I: Integer;
  WatchJson: String;
  SettingsJson: String;
  PasswordValue: String;
  AgentName: String;
begin
  WatchJson := '[';
  for I := 0 to WatchRoots.Items.Count - 1 do begin
    if I > 0 then WatchJson := WatchJson + ',';
    WatchJson := WatchJson + '"' + JsonEscape(WatchRoots.Items[I]) + '"';
  end;
  WatchJson := WatchJson + ']';
  PasswordValue := '';
  if not WazuhAlreadyEnrolled then PasswordValue := WazuhCredentialsPage.Values[0];
  AgentName := Trim(WazuhPage.Values[2]);
  SettingsJson := '{' +
    '"packagePath":"' + JsonEscape(PayloadFilePath) + '",' +
    '"packageSha256":"{#PayloadSha256}",' +
    '"wazuhManager":"' + JsonEscape(Trim(WazuhPage.Values[0])) + '",' +
    '"wazuhAgentGroup":"' + JsonEscape(Trim(WazuhPage.Values[1])) + '",' +
    '"wazuhAgentName":"' + JsonEscape(AgentName) + '",' +
    '"watchRoots":' + WatchJson + ',' +
    '"dlpControlPlaneUrl":"' + JsonEscape(Trim(DlpPage.Values[0])) + '",' +
    '"dlpEnrollmentToken":"' + JsonEscape(DlpPage.Values[1]) + '",' +
    '"wazuhRegistrationPassword":"' + JsonEscape(PasswordValue) + '"' +
    '}';
  Result := SettingsJson;
end;

procedure UpdateInstallationQueue;
var
  Contents: AnsiString;
  Line: String;
  P1: Integer;
  P2: Integer;
  StepNumber: Integer;
  Percent: Integer;
  MessageText: String;
begin
  if not LoadStringFromFile(SetupProgressPath, Contents) then Exit;
  Line := Utf8Decode(Contents);
  P1 := Pos('|', Line);
  if P1 = 0 then Exit;
  P2 := Pos('|', Copy(Line, P1 + 1, Length(Line)));
  if P2 = 0 then Exit;
  P2 := P2 + P1;
  StepNumber := StrToIntDef(Copy(Line, 1, P1 - 1), 0);
  Percent := StrToIntDef(Copy(Line, P1 + 1, P2 - P1 - 1), 0);
  MessageText := Copy(Line, P2 + 1, Length(Line));
  if (StepNumber < 1) or (StepNumber > 7) then Exit;
  while LastQueueStep < StepNumber do begin
    if LastQueueStep > 0 then QueueList.Items[LastQueueStep - 1] := '✓ ' + QueueTitles[LastQueueStep];
    LastQueueStep := LastQueueStep + 1;
    QueueList.Items.Add('● ' + QueueTitles[LastQueueStep]);
    QueueList.ItemIndex := QueueList.Items.Count - 1;
  end;
  QueueList.Items[StepNumber - 1] := '● ' + QueueTitles[StepNumber] + ' — ' + MessageText;
  QueuePage.SetText('Instalando RabbitDLP', MessageText);
  QueuePage.SetProgress(Percent, 100);
end;

function RunRabbitDlpInstaller: Boolean;
var
  ExecuteInfo: TShellExecuteInfo;
  WaitResult: Cardinal;
  ExitCode: Cardinal;
  ErrorText: String;
  PowerShellPath: String;
  Parameters: String;
  Settings: String;
  ErrorContents: AnsiString;
  AclResult: Integer;
begin
  Result := False;
  ErrorText := '';
  SetupSettingsPath := ExpandConstant('{tmp}\rabbitdlp-setup.json');
  SetupProgressPath := ExpandConstant('{tmp}\rabbitdlp-progress.txt');
  SetupErrorPath := SetupProgressPath + '.error';
  PayloadFilePath := ExpandConstant('{tmp}\{#PayloadName}');
  ExtractTemporaryFile('{#PayloadName}');
  Settings := BuildSetupSettings;
  if not SaveStringToFile(SetupSettingsPath, Utf8Encode(Settings), False) then begin
    ErrorText := 'No se pudieron preparar los datos temporales de RabbitDLP.';
    MsgBox(ErrorText, mbError, MB_OK);
    Exit;
  end;
  Settings := '';

  if not Exec(ExpandConstant('{sys}\icacls.exe'),
    '"' + SetupSettingsPath + '" /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F',
    ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, AclResult) or (AclResult <> 0) then begin
    DeleteFile(SetupSettingsPath);
    MsgBox('Windows no pudo restringir los permisos de los datos temporales de RabbitDLP.', mbError, MB_OK);
    Exit;
  end;

  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
    '"' + ExpandConstant('{app}\install-windows-endpoint.ps1') + '"' +
    ' -SetupConfigPath "' + SetupSettingsPath + '"' +
    ' -ProgressFilePath "' + SetupProgressPath + '"';

  QueuePage.SetText('Instalando RabbitDLP', 'Verificando el paquete y la arquitectura de Windows.');
  QueuePage.SetProgress(0, 100);
  QueuePage.Show;
  SetupProcessRunning := True;
  WizardForm.CancelButton.Enabled := False;
  LastQueueStep := 0;
  QueueList.Items.Clear;

  ExecuteInfo.cbSize := SizeOf(ExecuteInfo);
  ExecuteInfo.fMask := SEE_MASK_NOCLOSEPROCESS;
  ExecuteInfo.Wnd := WizardForm.Handle;
  ExecuteInfo.lpVerb := '';
  ExecuteInfo.lpFile := PowerShellPath;
  ExecuteInfo.lpParameters := Parameters;
  ExecuteInfo.lpDirectory := ExpandConstant('{tmp}');
  ExecuteInfo.nShow := SW_HIDE;
  ExecuteInfo.hInstApp := 0;
  ExecuteInfo.lpIDList := 0;
  ExecuteInfo.lpClass := '';
  ExecuteInfo.hkeyClass := 0;
  ExecuteInfo.dwHotKey := 0;
  ExecuteInfo.hMonitor := 0;
  ExecuteInfo.hProcess := 0;
  if not ShellExecuteEx(ExecuteInfo) then begin
    SetupProcessRunning := False;
    WizardForm.CancelButton.Enabled := True;
    QueuePage.Hide;
    DeleteFile(SetupSettingsPath);
    MsgBox('No se pudo iniciar el instalador de RabbitDLP.', mbError, MB_OK);
    Exit;
  end;

  try
    repeat
      WaitResult := WaitForSingleObject(ExecuteInfo.hProcess, 100);
      UpdateInstallationQueue;
      if WaitResult <> WAIT_OBJECT_0 then Sleep(100);
    until WaitResult <> WAIT_TIMEOUT;
    if WaitResult <> WAIT_OBJECT_0 then
      ErrorText := 'No se pudo confirmar que la instalación terminara correctamente.'
    else begin
      if not GetExitCodeProcess(ExecuteInfo.hProcess, ExitCode) then
        ErrorText := 'No se pudo confirmar que la instalación terminara correctamente.'
      else if ExitCode <> 0 then begin
        ErrorText := 'RabbitDLP no pudo completar la instalación. Revisa la conexión con Wazuh, la consola B89 y las carpetas seleccionadas.';
        if LoadStringFromFile(SetupErrorPath, ErrorContents) then
          ErrorText := Utf8Decode(ErrorContents)
        else
          ErrorText := ErrorText + #13#10#13#10 + 'El proceso no pudo entregar su diagnóstico temporal. Si existe, revisa C:\ProgramData\B89\RabbitDLP\Logs\install-last-error.txt.';
      end;
    end;
    UpdateInstallationQueue;
  finally
    CloseHandle(ExecuteInfo.hProcess);
    SetupProcessRunning := False;
    WizardForm.CancelButton.Enabled := True;
    QueuePage.Hide;
    DeleteFile(SetupSettingsPath);
    DeleteFile(SetupProgressPath);
    DeleteFile(SetupErrorPath);
  end;

  if ErrorText <> '' then begin
    MsgBox(ErrorText, mbError, MB_OK);
    Exit;
  end;

  QueueList.Items.Add('✓ ' + QueueTitles[7]);
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and not RunRabbitDlpInstaller then
    RaiseException('La instalación de RabbitDLP no se completó.');
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  if SetupProcessRunning then begin
    Cancel := False;
    Confirm := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usDone) and not UninstallSilent then
    MsgBox('RabbitDLP se quitó de este equipo. Para desconectarlo también de B89, revoca el equipo en DLP de endpoints.', mbInformation, MB_OK);
end;
