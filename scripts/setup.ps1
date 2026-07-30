#Requires -Version 5
<#
.SYNOPSIS
  ct-agent guided setup (Windows) -- a richer, optional alternative to the portal's
  thin `irm | iex` one-liner (CADS-Tunnel's /install.ps1). Checks your environment,
  walks you through a .env file, optionally grabs a starter template, installs +
  onboards the agent (directly on this host, or as a Docker container), then
  reports your tunnel's certificate tier (Rot/Gelb/Grün) and the commands you need
  to stop/reset it or go from Gelb to Grün.

.EXAMPLE
  ./scripts/setup.ps1                  # direct-host install (asks to confirm)
  ./scripts/setup.ps1 -Docker           # run as a Docker container instead
  ./scripts/setup.ps1 -Yes              # skip the sandbox-warning confirmation
  ./scripts/setup.ps1 -Template         # also fetch the starter site template
  ./scripts/setup.ps1 -Green            # push straight through to Grün (own cert)

.NOTES
  Env override: $env:CT_RELEASE_BASE (default: this repo's GitHub releases).
#>
[CmdletBinding()]
param(
  [switch]$Docker,
  [switch]$Yes,
  [switch]$Template,
  [switch]$Green
)

$ErrorActionPreference = 'Stop'

$ReleaseBase = if ($env:CT_RELEASE_BASE) { $env:CT_RELEASE_BASE } else { 'https://github.com/scimbe/ct-agent/releases/latest/download' }
$Mode = if ($Docker) { 'docker' } else { 'direct' }
$StateDir = if ($env:CT_AGENT_STATE_DIR) { $env:CT_AGENT_STATE_DIR } else { Join-Path (Get-Location) '.ct-agent-state' }
$PidFile = Join-Path (Get-Location) 'ct-agent.pid'

function Log($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  [ok] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Die($msg)  { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

# --- 1. environment check ------------------------------------------------------
function Test-Environment {
  Log "checking your environment"
  $script:Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64'   { 'x86_64' }
    'ARM64'   { 'aarch64' }
    'x86'     { 'i686' }
    default   { Die "unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'" }
  }
  Ok "arch: $($script:Arch)"

  if ($Mode -eq 'docker') {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
      Die "docker not found -- install Docker Desktop (https://docs.docker.com/get-docker/) and re-run with -Docker"
    }
    Ok "docker present"
  }
}

# --- 2. mode select + sandbox warning -------------------------------------------
function Confirm-Mode {
  if ($Mode -eq 'docker') { Log "mode: Docker container (recommended isolation)"; return }
  Log "mode: direct install on this host"
  Warn "ct-agent is a network-facing process that will run directly on this machine."
  Warn "It's designed to run inside an isolated environment (a VM, a container, or a"
  Warn "dedicated host) -- not on a machine holding data/credentials you wouldn't want"
  Warn "reachable if this agent were ever compromised. Prefer -Docker if unsure."
  if ($Yes) { Ok "proceeding (-Yes)"; return }
  $reply = Read-Host "Continue with a direct-host install? [y/N]"
  if ($reply -notmatch '^(y|yes)$') { Die "aborted" }
  Ok "confirmed"
}

# --- 3. .env handling -----------------------------------------------------------
$EnvTemplate = @'
# ct-agent tunnel config -- get these values from your tunnel's page on
# the portal (Install button), then re-run ./scripts/setup.ps1.
#
# Preferred: a single short-lived bootstrap token (never touches disk/history
# beyond this file); the script redeems it for real credentials server-side.
CT_BOOTSTRAP=

# Alternative to CT_BOOTSTRAP: the two tokens it would have redeemed into.
#CT_AGENT_JOIN_TOKEN=
#CT_AGENT_TOKEN=

# Your control plane (the portal's own URL).
CT_AGENT_CP_URL=https://bunsenbrenner.org

# The hostname the portal assigned (or you configured) for this tunnel.
CT_AGENT_HOSTNAME=

# Where your own site/service is actually running, and how ct-agent should
# forward to it. tcp+host:port for a plain backend; while your tunnel is
# Gelb, this origin must serve PLAIN HTTP (not TLS) -- see the Gelb->Gruen
# note this script prints after onboarding.
CT_AGENT_ORIGIN=127.0.0.1:8080
CT_AGENT_ORIGIN_PROTO=tcp
'@

function Import-DotEnv {
  Log "checking for .env"
  if (-not (Test-Path .env)) {
    Warn ".env not found in $(Get-Location)"
    Set-Content -Path .env.example -Value $EnvTemplate -NoNewline
    Warn "wrote .env.example -- copy it to .env, fill in the values from your portal"
    Warn "tunnel page, then re-run this script. Stopping here."
    exit 1
  }
  Ok ".env found"
  Get-Content .env | Where-Object { $_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$' } | ForEach-Object {
    $name = $Matches[1]; $value = $Matches[2]
    if ($name -and -not $name.StartsWith('#')) {
      Set-Item -Path "env:$name" -Value $value
    }
  }

  if ($env:CT_BOOTSTRAP) {
    Log "redeeming CT_BOOTSTRAP server-side"
    if (-not $env:CT_AGENT_CP_URL) { Die "set CT_AGENT_CP_URL in .env" }
    try {
      $resp = Invoke-RestMethod -Method Post -Uri "$($env:CT_AGENT_CP_URL.TrimEnd('/'))/bootstrap/redeem" `
        -ContentType 'application/json' -Body (ConvertTo-Json @{ token = $env:CT_BOOTSTRAP })
    } catch {
      Die "bootstrap redeem failed -- the token may be expired/already used"
    }
    $bundle = $resp.secret
    if ($bundle -match 'CT_JOIN_TOKEN=([^;]*)')  { $env:CT_AGENT_JOIN_TOKEN = $Matches[1] }
    if ($bundle -match 'CT_AGENT_TOKEN=([^;]*)') { $env:CT_AGENT_TOKEN     = $Matches[1] }
    Ok "bootstrap redeemed"
  }

  $missing = @()
  foreach ($v in 'CT_AGENT_CP_URL','CT_AGENT_HOSTNAME','CT_AGENT_ORIGIN','CT_AGENT_ORIGIN_PROTO') {
    if (-not (Get-Item "env:$v" -ErrorAction SilentlyContinue).Value) { $missing += $v }
  }
  if (-not $env:CT_AGENT_JOIN_TOKEN) { $missing += 'CT_AGENT_JOIN_TOKEN (or CT_BOOTSTRAP)' }
  if (-not $env:CT_AGENT_TOKEN)      { $missing += 'CT_AGENT_TOKEN (or CT_BOOTSTRAP)' }
  if ($missing.Count -gt 0) {
    Warn "missing/blank in .env: $($missing -join ', ')"
    Die "fill these in and re-run"
  }
  Ok "required variables present"

  # Deployment-wide defaults ct-agent needs but a customer wouldn't usually set by
  # hand. Missing CT_AGENT_EDGE_CERT_URL in particular makes the agent hang
  # forever, not just error, so this is defaulted rather than left optional.
  if (-not $env:CT_AGENT_MODE)          { $env:CT_AGENT_MODE = 'browser' }
  if (-not $env:CT_AGENT_EDGE_CERT_URL) { $env:CT_AGENT_EDGE_CERT_URL = $env:CT_AGENT_CP_URL }
  if (-not $env:CT_AGENT_ID)            { $env:CT_AGENT_ID = "agent-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())-$PID" }
  if (-not $env:CT_AGENT_EDGE) {
    try {
      $ni = Invoke-RestMethod -Uri "$($env:CT_AGENT_CP_URL.TrimEnd('/'))/network-info"
      $env:CT_AGENT_EDGE = $ni.mesh_edge_addr
    } catch { }
    if (-not $env:CT_AGENT_EDGE) { Die "could not determine CT_AGENT_EDGE automatically -- set it in .env (host:port of the mesh edge)" }
  }
  $env:CT_AGENT_STATE_DIR = $StateDir
}

# --- 4. optional template -------------------------------------------------------
function Install-Template {
  if (-not $Template) { return }
  Log "fetching the starter site template"
  New-Item -ItemType Directory -Force -Path template | Out-Null
  $zip = Join-Path 'template' 'hello-world-pipeline.zip'
  try {
    Invoke-WebRequest -Uri "$($env:CT_AGENT_CP_URL.TrimEnd('/'))/downloads/hello-world-pipeline.zip" -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath template -Force
    Remove-Item $zip
    Ok "template unpacked into ./template"
  } catch {
    Warn "template download failed -- skipping"
  }
}

# --- 5. install + onboard --------------------------------------------------------
function Install-Direct {
  $asset = "ct-agent-windows-$($script:Arch).exe"
  $url = "$ReleaseBase/$asset"
  Log "downloading $asset"
  Invoke-WebRequest -Uri $url -OutFile .\ct-agent.exe -UseBasicParsing
  Ok "ct-agent binary ready"

  if ((Test-Path $StateDir) -and (Get-ChildItem $StateDir -ErrorAction SilentlyContinue)) {
    Ok "existing state in $StateDir -- already onboarded, skipping onboard"
  } else {
    Log "onboarding (reads CT_AGENT_JOIN_TOKEN/CT_AGENT_TOKEN from the environment, never the command line)"
    & .\ct-agent.exe onboard
    if ($LASTEXITCODE -ne 0) { Die "onboarding failed" }
    Ok "onboarded"
  }

  Log "starting ct-agent in the background"
  $proc = Start-Process -FilePath .\ct-agent.exe -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput .\ct-agent.log -RedirectStandardError .\ct-agent.err.log
  Set-Content -Path $PidFile -Value $proc.Id
  Ok "running, pid $($proc.Id) (logs: .\ct-agent.log)"
}

function Install-Docker {
  Log "building the Docker image"
  # Build straight from this repo's git history (docker supports git-URL build
  # contexts natively) -- this script is commonly run with no local checkout.
  docker build -t ct-agent:local "https://github.com/scimbe/ct-agent.git#main:docker"
  if ($LASTEXITCODE -ne 0) { Die "docker build failed" }
  Log "starting the container"
  docker rm -f ct-agent 2>$null | Out-Null
  docker run -d --name ct-agent --env-file .env -v "${StateDir}:/state" -e CT_AGENT_STATE_DIR=/state ct-agent:local
  if ($LASTEXITCODE -ne 0) { Die "docker run failed" }
  Ok "container 'ct-agent' running (logs: docker logs -f ct-agent)"
}

# --- 6. bring up to Gelb (default) or Grün ---------------------------------------
$script:FinalStatus = 'unknown'
function Wait-ForTier {
  Log "checking certificate tier (Rot -> Gelb -> Grün)"
  $deadline = (Get-Date).AddSeconds(120)
  $status = ''
  $last = ''
  while ((Get-Date) -lt $deadline) {
    try {
      $resp = Invoke-RestMethod -Uri "$($env:CT_AGENT_CP_URL.TrimEnd('/'))/agent/acme-admission/$($env:CT_AGENT_TOKEN)/$($env:CT_AGENT_HOSTNAME)"
      $status = $resp.status
    } catch { $status = '' }
    if ($status -and $status -ne $last) {
      switch ($status) {
        'rot'   { Warn "Rot -- still being set up, waiting..." }
        'gelb'  { Ok "Gelb -- live now via the shared certificate" }
        'gruen' { Ok "Grün -- your own certificate, fully zero-knowledge" }
      }
      $last = $status
    }
    if ($status -eq 'gruen') { break }
    if ($status -eq 'gelb' -and -not $Green) { break }
    Start-Sleep -Seconds 3
  }

  if ($status -eq 'gelb' -and $Green) {
    Warn "Gelb->Grün: your origin ($($env:CT_AGENT_ORIGIN)) must serve PLAIN HTTP right now,"
    Warn "not TLS -- it only needs its own certificate once Grün is reached."
    Log "requesting your own certificate (ct-agent certificate)"
    $env:CT_ACME_CERT_OUT_DIR = if ($env:CT_ACME_CERT_OUT_DIR) { $env:CT_ACME_CERT_OUT_DIR } else { '.\ct-agent-cert' }
    Start-Process -FilePath .\ct-agent.exe -ArgumentList 'certificate' -WindowStyle Hidden `
      -RedirectStandardOutput .\ct-agent.log -RedirectStandardError .\ct-agent.err.log
    Ok "certificate issuance running in the background (watch .\ct-agent.log)"
  }
  $script:FinalStatus = if ($status) { $status } else { 'unknown' }
}

# --- 7. final report ---------------------------------------------------------------
function Show-FinalReport {
  Write-Host ""
  Log "done -- current tier: $($script:FinalStatus)"
  if ($Mode -eq 'docker') {
    Write-Host "  stop:   docker stop ct-agent"
    Write-Host "  reset:  docker rm -f ct-agent; Remove-Item -Recurse -Force '$StateDir'; ./scripts/setup.ps1 -Docker"
  } else {
    Write-Host "  stop:   Stop-Process -Id (Get-Content '$PidFile') -ErrorAction SilentlyContinue"
    Write-Host "  reset:  Stop-Process -Id (Get-Content '$PidFile') -ErrorAction SilentlyContinue; Remove-Item -Recurse -Force '$StateDir','$PidFile' -ErrorAction SilentlyContinue; ./scripts/setup.ps1"
    Write-Host "  rotate origin key only (keep the same tunnel): .\ct-agent.exe rotate"
  }
  Write-Host "  full revoke/delete of the tunnel itself: use the portal UI ($($env:CT_AGENT_CP_URL.TrimEnd('/'))/portal/tunnels) -- not scriptable today."
  if ($script:FinalStatus -eq 'gelb') {
    Write-Host ""
    Write-Host "  Still Gelb. To get your own certificate (Grün) once you're ready:"
    Write-Host "    1. Make sure $($env:CT_AGENT_ORIGIN) serves PLAIN HTTP (not TLS) for now."
    Write-Host "    2. `$env:CT_AGENT_CP_URL='$($env:CT_AGENT_CP_URL)'; `$env:CT_AGENT_TOKEN='$($env:CT_AGENT_TOKEN)'; `$env:CT_AGENT_HOSTNAME='$($env:CT_AGENT_HOSTNAME)'; .\ct-agent.exe certificate"
    Write-Host "    3. Once Grün, switch $($env:CT_AGENT_ORIGIN) back to serving its own TLS cert."
  }
}

Test-Environment
Confirm-Mode
Import-DotEnv
Install-Template
if ($Mode -eq 'docker') { Install-Docker } else { Install-Direct }
Wait-ForTier
Show-FinalReport
