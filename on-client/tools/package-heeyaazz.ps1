[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$OutputDirectory
)
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$appRoot = Split-Path -Parent $PSScriptRoot
$meta = Get-Content -LiteralPath (Join-Path $appRoot 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($meta.name -ne 'alekov-client-starter' -or $meta.version -notmatch '^\d+\.\d+\.\d+$') {
  throw '앱 package.json의 이름 또는 버전을 확인할 수 없습니다.'
}
if ($meta.engines.node -ne '24.19.0') {
  throw '이 배포 스크립트는 package.json에 지정된 Node.js 24.19.0 기준만 포장합니다.'
}

$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-Path -LiteralPath $outputRoot)) {
  New-Item -ItemType Directory -Path $outputRoot | Out-Null
} elseif ((Get-ChildItem -LiteralPath $outputRoot -Force | Measure-Object).Count -ne 0) {
  throw '출력 폴더가 비어 있지 않습니다. 기존 결과를 보존하고 새 빈 폴더를 지정하세요.'
}

$stage = Join-Path $outputRoot "Heeeyaazz-$($meta.version)"
$zipPath = Join-Path $outputRoot "Heeeyaazz-$($meta.version)-portable.zip"
if ((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $zipPath)) {
  throw '출력 위치에 같은 버전의 기존 결과가 있습니다. 이를 덮어쓰지 않고 새 빈 출력 폴더를 지정하세요.'
}
New-Item -ItemType Directory -Path $stage | Out-Null

$include = @(
  'public',
  'src',
  'student',
  'vendor',
  'tools',
  'docs',
  'package.json',
  'README.md',
  '.env.example'
)
foreach ($relative in $include) {
  $source = Join-Path $appRoot $relative
  if (-not (Test-Path -LiteralPath $source)) { throw "배포에 필요한 파일이 없습니다: $relative" }
  $destination = Join-Path $stage $relative
  $destinationParent = Split-Path -Parent $destination
  if (-not (Test-Path -LiteralPath $destinationParent)) { New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null }
  Copy-Item -LiteralPath $source -Destination $destination -Recurse
}

Compress-Archive -Path $stage -DestinationPath $zipPath -CompressionLevel Optimal
Write-Host "기본 패키지 생성: $zipPath"
Write-Host '포함 범위: 공개 앱 파일, 소스 모듈, 학생 표시 코드, vendor 고지, 시작 도구, 무비밀 설정 예시와 안내 문서.'
Write-Host '제외 범위: .env, 개인 인증 자료, 외부 데이터베이스, Git 기록, 제출 원문 묶음.'

$compiler = Get-Command 'ISCC.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $compiler) {
  throw '기본 ZIP은 준비됐지만 ISCC.exe를 찾지 못해 setup.exe는 만들지 않았습니다. Inno Setup을 설치하고 ISCC.exe를 PATH에 추가한 뒤 새 빈 출력 폴더로 다시 실행하세요.'
}
$iss = Join-Path $appRoot 'installer\Heeeyaazz.iss'
& $compiler.Source "/DAppVersion=$($meta.version)" "/DStageDir=$stage" "/DOutputDir=$outputRoot" $iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup 컴파일에 실패했습니다. 종료 코드: $LASTEXITCODE" }
$setupPath = Join-Path $outputRoot "Heeeyaazz-Setup-$($meta.version).exe"
if (-not (Test-Path -LiteralPath $setupPath)) { throw 'ISCC가 성공 코드를 반환했지만 setup.exe 파일을 찾지 못했습니다.' }
Write-Host "사용자 단위 설치 프로그램 생성: $setupPath"
Write-Host '설치 프로그램은 Node.js를 포함하지 않습니다. 대상 PC에 Node.js 24.19.0이 필요합니다.'
