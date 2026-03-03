[CmdletBinding()]
param(
  [ValidateSet("patch", "minor", "major", "none")]
  [string]$Bump = "patch",
  [switch]$Publish,
  [switch]$Commit,
  [switch]$Tag,
  [switch]$SkipChecks,
  [switch]$AllowDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-CheckedCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$File,
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  Write-Host "==> $File $($Arguments -join ' ')"
  & $File @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code ${LASTEXITCODE}: $File $($Arguments -join ' ')"
  }
}

function Get-NextVersion {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Current,
    [Parameter(Mandatory = $true)]
    [string]$Level
  )

  if ($Level -eq "none") {
    return $Current
  }

  if ($Current -notmatch "^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)$") {
    throw "Unsupported version format '$Current'. Expected plain semver like 2.1.1"
  }

  $major = [int]$Matches.major
  $minor = [int]$Matches.minor
  $patch = [int]$Matches.patch

  switch ($Level) {
    "patch" {
      $patch += 1
    }
    "minor" {
      $minor += 1
      $patch = 0
    }
    "major" {
      $major += 1
      $minor = 0
      $patch = 0
    }
    default {
      throw "Unsupported bump level '$Level'"
    }
  }

  return "$major.$minor.$patch"
}

function Read-PackageJson {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )
  return (Get-Content -Raw -Path $Path | ConvertFrom-Json)
}

function Write-PackageJson {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [object]$Data
  )

  $json = $Data | ConvertTo-Json -Depth 100
  $fullPath = [System.IO.Path]::GetFullPath($Path)
  $encoding = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($fullPath, "$json`n", $encoding)
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
Set-Location $repoRoot

$packageFiles = @(
  "packages/core/package.json",
  "packages/node/package.json",
  "packages/browser/package.json"
)

$publishOrder = @(
  "@unknownncat/curve25519-core",
  "@unknownncat/curve25519-node",
  "@unknownncat/curve25519-browser"
)

$corePackageName = "@unknownncat/curve25519-core"

if (-not $AllowDirty) {
  $statusOutput = git status --porcelain
  if ($LASTEXITCODE -ne 0) {
    throw "Could not read git status. Ensure git is installed and repository is initialized."
  }
  if ($statusOutput) {
    throw "Working tree is not clean. Commit or stash changes first, or rerun with -AllowDirty."
  }
}

$packages = @()
foreach ($file in $packageFiles) {
  $packages += [pscustomobject]@{
    Path = $file
    Json = Read-PackageJson -Path $file
  }
}

$versions = @($packages | ForEach-Object { $_.Json.version } | Sort-Object -Unique)
if ($versions.Count -ne 1) {
  throw "Package versions are not aligned: $($versions -join ', ')"
}

$currentVersion = [string]$versions[0]
$nextVersion = Get-NextVersion -Current $currentVersion -Level $Bump

Write-Host "Current version: $currentVersion"
Write-Host "Target version:  $nextVersion"

if ($Bump -ne "none") {
  foreach ($entry in $packages) {
    $entry.Json.version = $nextVersion

    if ($entry.Json.PSObject.Properties.Name -contains "dependencies") {
      if ($entry.Json.dependencies.PSObject.Properties.Name -contains $corePackageName) {
        $entry.Json.dependencies.$corePackageName = $nextVersion
      }
    }
  }

  foreach ($entry in $packages) {
    Write-PackageJson -Path $entry.Path -Data $entry.Json
    Write-Host "Updated $($entry.Path) -> $nextVersion"
  }

  Invoke-CheckedCommand -File "npm" -Arguments @("install", "--package-lock-only")
}

if (-not $SkipChecks) {
  $hadRequireWasmOpt = Test-Path Env:CURVE25519_REQUIRE_WASM_OPT
  $previousRequireWasmOpt = if ($hadRequireWasmOpt) { $env:CURVE25519_REQUIRE_WASM_OPT } else { $null }
  $env:CURVE25519_REQUIRE_WASM_OPT = "1"
  try {
    Invoke-CheckedCommand -File "npm" -Arguments @("run", "release:check")
  } finally {
    if ($hadRequireWasmOpt) {
      $env:CURVE25519_REQUIRE_WASM_OPT = $previousRequireWasmOpt
    } else {
      Remove-Item Env:CURVE25519_REQUIRE_WASM_OPT -ErrorAction SilentlyContinue
    }
  }
}

if ($Publish) {
  foreach ($packageName in $publishOrder) {
    Invoke-CheckedCommand -File "npm" -Arguments @("publish", "--access", "public", "-w", $packageName)
  }
}

if ($Commit) {
  $addArgs = @("add", "package-lock.json") + $packageFiles
  Invoke-CheckedCommand -File "git" -Arguments $addArgs
  Invoke-CheckedCommand -File "git" -Arguments @("commit", "-m", "chore(release): v$nextVersion")
}

if ($Tag) {
  Invoke-CheckedCommand -File "git" -Arguments @("tag", "v$nextVersion")
}

Write-Host ""
Write-Host "Release automation finished."
Write-Host "Version: $nextVersion"
if ($Tag) {
  Write-Host "Tag created: v$nextVersion"
}
Write-Host "If you created commit/tag, push manually with:"
Write-Host "  git push origin HEAD"
if ($Tag) {
  Write-Host "  git push origin v$nextVersion"
}
