#Requires -Version 5
<#
Regression test for scripts/setup.ps1's Install-Docker -- the Windows-side
mirror of scripts/tests/test-setup-sh-secrets-docker.sh:
 - the container must get every value Import-DotEnv resolved (redeemed tokens,
   CT_AGENT_ID, CT_AGENT_EDGE, ...), with or without a .env file;
 - secret values must not appear in docker's argv;
 - the image must be built from the latest release tag, not `#main`.
`docker` is a stub on PATH that records argv and the values of `-e NAME`;
Invoke-RestMethod is overridden in the child session. No daemon, no network.
Skipped on Windows hosts (the stub is a POSIX shell script).

  pwsh -File scripts/tests/test-setup-ps1-docker.ps1
#>

$ErrorActionPreference = 'Stop'
if ($IsWindows) { Write-Host "SKIP: POSIX docker stub"; exit 0 }
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$SetupPs1 = Join-Path $RepoRoot 'scripts' 'setup.ps1'
$script:Fail = $false

function Check($desc, [bool]$cond, $detail = '') {
  if ($cond) { Write-Host "ok: $desc" -ForegroundColor Green }
  else { Write-Host "FAIL: $desc $detail" -ForegroundColor Red; $script:Fail = $true }
}

$stubs = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $stubs | Out-Null
$dockerStub = @'
#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
if [ "$1" = "run" ]; then
  prev=""
  for a in "$@"; do
    if [ "$prev" = "-e" ]; then
      case "$a" in *=*) echo "ENV $a" ;; *) eval "v=\${$a-__UNSET__}"; echo "ENV $a=$v" ;; esac
    fi
    prev="$a"
  done >> "$STUB_ENV"
fi
exit 0
'@
Set-Content -Path (Join-Path $stubs 'docker') -Value $dockerStub -NoNewline
chmod +x (Join-Path $stubs 'docker')

function Invoke-DockerCase([string]$WorkDir, [hashtable]$EnvVars) {
  $envSetters = ($EnvVars.GetEnumerator() | ForEach-Object { "`$env:$($_.Key) = '$($_.Value)'" }) -join '; '
  $script = @"
Set-Location '$WorkDir'
`$env:PATH = '$stubs' + [IO.Path]::PathSeparator + `$env:PATH
`$env:STUB_LOG = '$WorkDir/argv.log'
`$env:STUB_ENV = '$WorkDir/env.log'
$envSetters
. '$SetupPs1'
function Invoke-RestMethod {
  param([string]`$Uri, [string]`$Method, [string]`$ContentType, `$Body)
  if (`$Uri -like '*bootstrap/redeem') { return [pscustomobject]@{ secret = 'CT_JOIN_TOKEN=redeemedjoin;CT_AGENT_TOKEN=redeemedagent' } }
  if (`$Uri -like '*releases/latest')  { return [pscustomobject]@{ tag_name = 'v9.9.9' } }
  if (`$Uri -like '*network-info')     { return [pscustomobject]@{ mesh_edge_port = 4433 } }
  throw "unexpected Invoke-RestMethod `$Uri"
}
`$Mode = 'docker'
Import-DotEnv
Install-Docker
Write-Output 'DOCKER_OK'
"@
  $out = & pwsh -NoProfile -NonInteractive -Command $script 2>&1 | Out-String
  return @{ Output = $out; ExitCode = $LASTEXITCODE }
}

function Read-Or-Empty($path) { if (Test-Path $path) { Get-Content $path } else { @() } }

# --- case 1: bootstrap one-liner shape, no .env file.
$d1 = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $d1 | Out-Null
$r1 = Invoke-DockerCase -WorkDir $d1 -EnvVars @{
  CT_BOOTSTRAP = 'sekritbootstrap'; CT_AGENT_CP_URL = 'https://cp.example'
  CT_AGENT_HOSTNAME = 'demo.example'; CT_AGENT_ORIGIN = '10.0.0.5:8080'
}
Check "case 1 completed" ($r1.Output -match 'DOCKER_OK') $r1.Output
$argv1 = (Read-Or-Empty "$d1/argv.log") -join "`n"
$env1 = Read-Or-Empty "$d1/env.log"
Check "case 1 built from the release tag" ($argv1 -match 'ct-agent\.git#v9\.9\.9:docker') $argv1
Check "case 1 kept secrets out of docker argv" (-not ($argv1 -match 'sekritbootstrap|redeemedjoin|redeemedagent')) $argv1
Check "case 1 passed no --env-file without a .env" (-not ($argv1 -match '--env-file')) $argv1
foreach ($want in 'CT_AGENT_JOIN_TOKEN=redeemedjoin','CT_AGENT_TOKEN=redeemedagent','CT_AGENT_EDGE=cp.example:4433',
                  'CT_AGENT_EDGE_CERT_URL=https://cp.example','CT_AGENT_MODE=browser','CT_AGENT_STATE_DIR=/state',
                  'CT_AGENT_CAPABILITY_OUT=/state/capability.bin') {
  Check "case 1 container gets $want" ($env1 -contains "ENV $want") ($env1 -join '; ')
}
Check "case 1 container gets CT_AGENT_ID" (@($env1 | Where-Object { $_ -match '^ENV CT_AGENT_ID=agent-\d+-\d+$' }).Count -eq 1) ($env1 -join '; ')
Check "case 1 mounted an absolute state dir" ($argv1 -match [regex]::Escape("-v $d1/.ct-agent-state:/state")) $argv1
Remove-Item -Recurse -Force $d1

# --- case 2: .env present -> still passed, loopback origin warned about.
$d2 = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $d2 | Out-Null
Set-Content -Path (Join-Path $d2 '.env') -Value @"
CT_AGENT_JOIN_TOKEN=filejoin
CT_AGENT_TOKEN=filetoken
CT_AGENT_CP_URL=https://cp.example
CT_AGENT_HOSTNAME=demo.example
CT_AGENT_ORIGIN=127.0.0.1:8080
"@
$r2 = Invoke-DockerCase -WorkDir $d2 -EnvVars @{}
Check "case 2 completed" ($r2.Output -match 'DOCKER_OK') $r2.Output
$argv2 = (Read-Or-Empty "$d2/argv.log") -join "`n"
$env2 = Read-Or-Empty "$d2/env.log"
Check "case 2 kept --env-file .env" ($argv2 -match '--env-file \.env') $argv2
Check "case 2 container gets CT_AGENT_TOKEN=filetoken" ($env2 -contains 'ENV CT_AGENT_TOKEN=filetoken') ($env2 -join '; ')
Check "case 2 warned about a loopback origin" ($r2.Output -match 'is loopback') $r2.Output
Remove-Item -Recurse -Force $d2, $stubs

if ($script:Fail) { Write-Host "FAIL: setup.ps1 Install-Docker regressed"; exit 1 }
Write-Host "PASS: setup.ps1 Install-Docker pins the release and hands the container its full config"
