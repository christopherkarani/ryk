param(
    [string]$Version,
    [string]$Commit = $(if ($env:RYK_COMMIT) { $env:RYK_COMMIT } else { "unknown" }),
    [string]$BuildDate = $(if ($env:RYK_BUILD_DATE) { $env:RYK_BUILD_DATE } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }),
    [string]$DistDir = $(if ($env:RYK_DIST_DIR) { $env:RYK_DIST_DIR } else { "dist" }),
    [string]$PostHogProjectToken = $(if ($env:RYK_POSTHOG_PROJECT_TOKEN) { $env:RYK_POSTHOG_PROJECT_TOKEN } else { "" }),
    [switch]$ArchiveOnly
)

$ErrorActionPreference = "Stop"
$telemetryBuildDisabled = $env:RYK_TELEMETRY_BUILD_DISABLED -eq "1"
if ($env:RYK_RELEASE_LIVE -eq "1" -and $telemetryBuildDisabled) {
    throw "Live releases cannot disable telemetry transport."
}
if (-not $telemetryBuildDisabled -and -not $PostHogProjectToken) {
    throw "RYK_POSTHOG_PROJECT_TOKEN is required for a release build (or set RYK_TELEMETRY_BUILD_DISABLED=1 for a local dry-run)."
}
if ($telemetryBuildDisabled) {
    $PostHogProjectToken = ""
}

if (-not $Version) {
    if ($env:RYK_VERSION) {
        $Version = $env:RYK_VERSION
    } else {
        $versionPath = Join-Path $PSScriptRoot "..\VERSION"
        if (-not (Test-Path -LiteralPath $versionPath)) {
            throw "Version is required when scripts/build-release.ps1 is not run from a checkout; pass -Version or set RYK_VERSION."
        }
        $Version = (Get-Content -LiteralPath $versionPath -TotalCount 1).Trim()
    }
}

$targets = @(
    @{ Os = "darwin"; Arch = "amd64"; Zig = "x86_64-macos"; Ext = "tar.gz"; Bin = "ryk" },
    @{ Os = "darwin"; Arch = "arm64"; Zig = "aarch64-macos"; Ext = "tar.gz"; Bin = "ryk" },
    @{ Os = "linux"; Arch = "amd64"; Zig = "x86_64-linux"; Ext = "tar.gz"; Bin = "ryk" },
    @{ Os = "linux"; Arch = "arm64"; Zig = "aarch64-linux"; Ext = "tar.gz"; Bin = "ryk" },
    @{ Os = "windows"; Arch = "amd64"; Zig = "x86_64-windows"; Ext = "zip"; Bin = "ryk.exe" }
)

function Copy-ReleasePayload($Root) {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $payloadRoots = @(
        "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md",
        "docs", "policies", "schemas", "fixtures", "examples",
        "packages", "packaging", "scripts", "integrations", "ryk-pi"
    )
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "Release payload staging requires git to copy only tracked files."
    }
    $tracked = @(& git -C $repoRoot ls-files -- @payloadRoots)
    if ($LASTEXITCODE -ne 0) {
        throw "Release payload staging failed: git ls-files exited $LASTEXITCODE."
    }
    if (-not $tracked) {
        throw "Release payload staging listed no tracked files."
    }

    New-Item -ItemType Directory -Force -Path $Root | Out-Null
    foreach ($rel in $tracked) {
        if ([string]::IsNullOrWhiteSpace($rel)) { continue }
        $src = Join-Path $repoRoot $rel
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) {
            continue
        }
        $dest = Join-Path $Root $rel
        $destDir = Split-Path -Parent $dest
        if (-not (Test-Path -LiteralPath $destDir)) {
            New-Item -ItemType Directory -Force -Path $destDir | Out-Null
        }
        Copy-Item -LiteralPath $src -Destination $dest
    }
    Get-ChildItem -LiteralPath $Root -Recurse -Force -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @("__pycache__", ".pytest_cache") } |
        Remove-Item -Recurse -Force
    Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @(".pyc", ".pyo") } |
        Remove-Item -Force

    $scanner = Join-Path $PSScriptRoot "check-release-payload-secrets.sh"
    if (-not (Get-Command bash -ErrorAction SilentlyContinue)) {
        throw "Release payload secret scanner requires bash; refusing to continue without a scan."
    }
    if (-not (Test-Path -LiteralPath $scanner)) {
        throw "Release payload secret scanner is missing: $scanner"
    }
    & bash $scanner $Root
    if ($LASTEXITCODE -ne 0) {
        throw "Release payload secret scan failed."
    }
}

function Assert-ReleaseTelemetry($Path) {
    $text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Path))
    if ($telemetryBuildDisabled) {
        if (-not $text.Contains("ryk-telemetry-transport-disabled-v1")) {
            throw "Release binary is not transport-disabled: $Path"
        }
        return
    }
    if (-not $text.Contains("ryk-telemetry-transport-enabled-v1")) {
        throw "Release binary is not transport-enabled: $Path"
    }
    if (-not $text.Contains($PostHogProjectToken)) {
        throw "Release binary does not contain the configured PostHog transport token: $Path"
    }
}

if (Test-Path -LiteralPath $DistDir) { Remove-Item -LiteralPath $DistDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

foreach ($target in $targets) {
    $artifact = "ryk-v$Version-$($target.Os)-$($target.Arch).$($target.Ext)"
    $work = Join-Path $DistDir "work/$($target.Os)-$($target.Arch)"
    $prefix = Join-Path $work "prefix"
    $root = Join-Path $work "ryk-v$Version-$($target.Os)-$($target.Arch)"

    New-Item -ItemType Directory -Force -Path $prefix, $root | Out-Null
    zig build install-ryk -Dtarget=$($target.Zig) -Doptimize=ReleaseSafe -Dversion=$Version -Dcommit=$Commit -Dbuild-date=$BuildDate -Dposthog-project-token=$PostHogProjectToken --prefix $prefix
    Assert-ReleaseTelemetry (Join-Path $prefix "bin/$($target.Bin)")

    Copy-ReleasePayload $root
    New-Item -ItemType Directory -Force -Path (Join-Path $root "bin") | Out-Null
    Copy-Item -LiteralPath (Join-Path $prefix "bin/$($target.Bin)") -Destination (Join-Path $root "bin/$($target.Bin)")
    # CLI-only: Zig shell_engine evaluates in-process (no ryk-daemon product binary).

    if ($target.Ext -eq "zip") {
        Compress-Archive -LiteralPath $root -DestinationPath (Join-Path $DistDir $artifact) -Force
    } else {
        tar -C $work -czf (Join-Path $DistDir $artifact) (Split-Path -Leaf $root)
    }
    Write-Host "Built $(Join-Path $DistDir $artifact)"
}

if ($env:RYK_SIGNING_ENABLED -eq "1") {
    if (-not $env:RYK_SIGNING_COMMAND) {
        Write-Error "Signing requested but RYK_SIGNING_COMMAND is not set."
        exit 1
    }
    Invoke-Expression $env:RYK_SIGNING_COMMAND
} else {
    Write-Host "Signing skipped; set RYK_SIGNING_ENABLED=1 and RYK_SIGNING_COMMAND in release environments."
}

$checksumsPath = Join-Path $DistDir "checksums.txt"
$checksumLines = foreach ($artifact in Get-ChildItem -LiteralPath $DistDir -File | Where-Object { $_.Name -like "ryk-v*.tar.gz" -or $_.Name -like "ryk-v*.zip" } | Sort-Object Name) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact.FullName).Hash.ToLowerInvariant()
    "$hash  $($artifact.Name)"
}
if (-not $checksumLines) {
    Write-Error "No release artifacts found in $DistDir"
    exit 1
}
$checksumLines | Set-Content -LiteralPath $checksumsPath -Encoding ASCII
Write-Host "Wrote $checksumsPath"

$telemetryContractPath = Join-Path $DistDir "telemetry-contract.txt"
$transport = if ($telemetryBuildDisabled) { "disabled" } else { "enabled" }
@(
    "telemetry_schema_version=1"
    "transport=$transport"
    "endpoint=https://us.i.posthog.com/batch/"
) | Set-Content -LiteralPath $telemetryContractPath -Encoding ASCII
Write-Host "Wrote $telemetryContractPath"

$sbomPath = Join-Path $DistDir "sbom.json"
$sbom = [ordered]@{
    sbom_format = "placeholder"
    name = "ryk-core"
    version = $Version
    generator = "scripts/build-release.ps1"
    status = "hook-only"
    note = "This release includes a hook-only inventory. Replace it with CycloneDX or SPDX output in the release environment when an SBOM tool is available."
    components = @(
        [ordered]@{
            name = "ryk"
            type = "application"
            language = "zig"
            dependencies = @()
        }
    )
}
$sbom | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $sbomPath -Encoding ASCII
Write-Host "Wrote $sbomPath"

if (-not $ArchiveOnly) {
    Write-Error "scripts/build-release.ps1 builds ryk archive fixtures only and does not produce release-manifest.json/package-manifests. Use scripts/build-release.sh for production release verification, or pass -ArchiveOnly for local archive smoke tests."
    exit 1
}
