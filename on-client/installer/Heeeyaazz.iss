#define AppName "Heeeyaazz"
#ifndef AppVersion
  #define AppVersion "0.2.11"
#endif
#ifndef StageDir
  #error StageDir must be provided by package-heeyaazz.ps1
#endif
#ifndef OutputDir
  #error OutputDir must be provided by package-heeyaazz.ps1
#endif

[Setup]
AppId={{CF299875-C679-4B6E-81E1-4B4D01050534}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Heeeyaazz
DefaultDirName={localappdata}\Programs\Heeeyaazz
DefaultGroupName=Heeeyaazz
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
Uninstallable=yes
OutputDir={#OutputDir}
OutputBaseFilename=Heeeyaazz-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Heeeyaazz"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\start-alekov.ps1"""; WorkingDir: "{app}"; Comment: "Heeeyaazz 로컬 보안 Agent 시작"
