#Requires -Version 5
<#
Regression test for scripts/setup.ps1's Import-DotEnv gate -- the exact
Windows-side mirror of scripts/tests/test-setup-sh-ensure-env.sh's three cases.

Real gap this guards against (found live while writing help.bunsenbrenner.org's
sandbox-instructions section): Import-DotEnv used to unconditionally require a
real .env FILE on disk, even when the one secret that actually matters
($env:CT_BOOTSTRAP, or $env:CT_AGENT_JOIN_TOKEN + $env:CT_AGENT_TOKEN) was
already sitting right there in the process environment -- meaning the portal's
own advertised one-liner ($env:CT_BOOTSTRAP='...'; irm ... | iex,
installer.rs's install_one_liner_bootstrap) could never actually complete
non-interactively.

Dot-sources setup.ps1 directly (safe: the $MyInvocation.InvocationName guard
at the bottom of setup.ps1 means dot-sourcing it defines functions only, it
never calls Invoke-Main or touches the network/filesystem beyond what a test
explicitly does).

  pwsh -File scripts/tests/test-setup-ps1-import-dotenv.ps1
#>

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$SetupPs1 = Join-Path $RepoRoot 'scripts' 'setup.ps1'
$script:Fail = $false

function Assert-Eq($desc, $expected, $actual) {
  if ($expected -ne $actual) {
    Write-Host "FAIL: $desc (expected [$expected], got [$actual])" -ForegroundColor Red
    $script:Fail = $true
  } else {
    Write-Host "ok: $desc" -ForegroundColor Green
  }
}

function Invoke-Case([string]$WorkDir, [hashtable]$EnvVars) {
  $envSetters = ($EnvVars.GetEnumerator() | ForEach-Object { "`$env:$($_.Key) = '$($_.Value)'" }) -join '; '
  $script = @"
Set-Location '$WorkDir'
$envSetters
. '$SetupPs1'
try {
  Import-DotEnv
  Write-Output 'IMPORT_DOTENV_OK'
} catch {
  Write-Output "IMPORT_DOTENV_DIED: `$(`$_.Exception.Message)"
  exit 1
}
"@
  $out = & pwsh -NoProfile -NonInteractive -Command $script 2>&1 | Out-String
  return @{ Output = $out; ExitCode = $LASTEXITCODE }
}

# --- case 1: no .env file, but the essential secret is already in the environment (the real one-liner shape) ---
$dir1 = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $dir1 | Out-Null
$r1 = Invoke-Case -WorkDir $dir1 -EnvVars @{
  CT_AGENT_JOIN_TOKEN = 'dummyjoin'; CT_AGENT_TOKEN = 'dummytoken'
  CT_AGENT_CP_URL = 'https://example.invalid'; CT_AGENT_HOSTNAME = 'demo.example'
  CT_AGENT_ORIGIN = '127.0.0.1:8080'; CT_AGENT_EDGE = 'example.invalid:4433'
}
Assert-Eq 'case 1 (env-only one-liner shape) exits 0' 0 $r1.ExitCode
if ($r1.Output -match 'IMPORT_DOTENV_OK') { Write-Host 'ok: case 1 reached end of Import-DotEnv' -ForegroundColor Green }
else { Write-Host "FAIL: case 1 did not reach end of Import-DotEnv -- output: $($r1.Output)" -ForegroundColor Red; $script:Fail = $true }
if ($r1.Output -match '\.env not found') { Write-Host "FAIL: case 1 should not need a real .env file: $($r1.Output)" -ForegroundColor Red; $script:Fail = $true }
else { Write-Host 'ok: case 1 did not demand a .env file' -ForegroundColor Green }
Remove-Item -Recurse -Force $dir1 -ErrorAction SilentlyContinue

# --- case 2: a real .env file present (the pre-existing, still-supported path) ---
$dir2 = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $dir2 | Out-Null
@'
CT_AGENT_JOIN_TOKEN=fromfile
CT_AGENT_TOKEN=fromfiletoken
CT_AGENT_CP_URL=https://example.invalid
CT_AGENT_HOSTNAME=demo.example
CT_AGENT_ORIGIN=127.0.0.1:9090
CT_AGENT_EDGE=example.invalid:4433
'@ | Set-Content -Path (Join-Path $dir2 '.env') -NoNewline
$r2 = Invoke-Case -WorkDir $dir2 -EnvVars @{}
Assert-Eq 'case 2 (.env file present) exits 0' 0 $r2.ExitCode
if ($r2.Output -match 'IMPORT_DOTENV_OK') { Write-Host 'ok: case 2 reached end of Import-DotEnv' -ForegroundColor Green }
else { Write-Host "FAIL: case 2 did not reach end of Import-DotEnv -- output: $($r2.Output)" -ForegroundColor Red; $script:Fail = $true }
Remove-Item -Recurse -Force $dir2 -ErrorAction SilentlyContinue

# --- case 3: neither a .env file nor the secret in env -- must still guide the user, not silently proceed ---
$dir3 = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $dir3 | Out-Null
$r3 = Invoke-Case -WorkDir $dir3 -EnvVars @{}
Assert-Eq 'case 3 (nothing provided) exits 1' 1 $r3.ExitCode
if (Test-Path (Join-Path $dir3 '.env.example')) { Write-Host 'ok: case 3 wrote .env.example so the customer has something to fill in' -ForegroundColor Green }
else { Write-Host 'FAIL: case 3 did not write .env.example' -ForegroundColor Red; $script:Fail = $true }
Remove-Item -Recurse -Force $dir3 -ErrorAction SilentlyContinue

if ($script:Fail) {
  Write-Host 'FAIL: one or more Import-DotEnv cases regressed' -ForegroundColor Red
  exit 1
} else {
  Write-Host 'PASS: all Import-DotEnv cases behaved correctly' -ForegroundColor Green
  exit 0
}
