param(
    [string]$Version,
    [string]$BaseUrl = $(if ($env:RYK_BASE_URL) { $env:RYK_BASE_URL } else { $null }),
    [string]$InstallDir = $(if ($env:RYK_INSTALL_DIR) { $env:RYK_INSTALL_DIR } else { Join-Path $HOME ".ryk\bin" }),
    [string]$ShareDir = $(if ($env:RYK_SHARE_DIR) { $env:RYK_SHARE_DIR } else { Join-Path $HOME ".ryk\share" }),
    [string]$ArtifactDir = $(if ($env:RYK_ARTIFACT_DIR) { $env:RYK_ARTIFACT_DIR } else { $null })
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Version) {
    if ($env:RYK_VERSION) {
        $Version = $env:RYK_VERSION
    } else {
        $defaultVersionPath = Join-Path (Resolve-Path (Join-Path $scriptDir "..")) "VERSION"
        if (Test-Path -LiteralPath $defaultVersionPath) {
            $Version = (Get-Content -LiteralPath $defaultVersionPath -TotalCount 1).Trim()
        } else {
            throw "Version is required when scripts/install.ps1 is not run from a checkout; pass -Version or set RYK_VERSION."
        }
    }
}
if (-not $BaseUrl) {
    $BaseUrl = "https://github.com/christopherkarani/ryk/releases/download/v$Version"
}

$ResourceRoot = if ($env:RYK_RESOURCE_ROOT) { $env:RYK_RESOURCE_ROOT } else { Join-Path $ShareDir $Version }
$CurrentLink = Join-Path $ShareDir "current"
$RuntimeDirs = @("integrations", "fixtures", "schemas", "policies", "ryk-pi")

$Quiet = ($env:RYK_INSTALL_QUIET -eq "1")
# Errors may still use color when the host supports it; quiet only suppresses non-error UI.
$HostSupportsColor = -not $env:NO_COLOR -and ($null -ne $Host.UI.RawUI)
$UseColor = -not $Quiet -and $HostSupportsColor

function Write-Ui([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    if ($Quiet) { return }
    if ($UseColor) {
        Write-Host $Message -ForegroundColor $Color
    } else {
        Write-Host $Message
    }
}

function Write-HostColor([string]$Message, [ConsoleColor]$Color) {
    if ($HostSupportsColor) {
        Write-Host $Message -ForegroundColor $Color
    } else {
        Write-Host $Message
    }
}

function Write-StepDone([string]$Label, [string]$Detail = "") {
    if ($Detail) {
        Write-Ui ("  + " + $Label + "  " + $Detail) Green
    } else {
        Write-Ui ("  + " + $Label) Green
    }
}

function Write-StepActive([string]$Label) {
    Write-Ui ("  > " + $Label) Green
}

function Write-HostHint {
    # Optional one-line next step. Not leftover homework.
    Write-Host "    ryk claude"
}

function Fail($Message, $Remediation = $null) {
    Write-Host ""
    Write-HostColor ("  x " + $Message) Red
    if ($Remediation) {
        foreach ($line in ($Remediation -split "`n")) {
            if ($line) { Write-HostColor ("    " + $line) DarkGray }
        }
    }
    Write-Host ""
    Write-HostColor "  Help  Run 'ryk help' after resolving the install error." DarkGray
    exit 1
}

function Detect-OS {
    if ($env:RYK_OS_OVERRIDE) { return $env:RYK_OS_OVERRIDE.ToLowerInvariant() }
    if ($IsWindows -or $env:OS -eq "Windows_NT") { return "windows" }
    Fail "unsupported operating system for install.ps1" "Use scripts/install.sh on macOS/Linux."
}

function Detect-Arch {
    $arch = if ($env:RYK_ARCH_OVERRIDE) { $env:RYK_ARCH_OVERRIDE } else { [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
    switch ($arch.ToLowerInvariant()) {
        "x64" { return "amd64" }
        "x86_64" { return "amd64" }
        "amd64" { return "amd64" }
        default { Fail "unsupported architecture: $arch" "Supported: amd64 (x64)." }
    }
}

function Get-ChecksumEntry($ChecksumsPath, $ArtifactName) {
    foreach ($line in Get-Content -LiteralPath $ChecksumsPath) {
        $parts = $line -split "\s+"
        if ($parts.Length -ge 2 -and $parts[1] -eq $ArtifactName) {
            return $parts[0].ToLowerInvariant()
        }
    }
    return $null
}

# Windows install is checksum-only (unsigned). This script verifies SHA-256
# against checksums.txt and does not consume checksums.txt.minisig. The POSIX
# installer (scripts/install.sh) is the minisign path; signing is not yet
# active until the public key is provisioned. See docs/release-signing.md.
function Verify-Checksum($ArtifactPath, $ChecksumsPath, $ArtifactName) {
    if (-not (Test-Path -LiteralPath $ChecksumsPath)) {
        Fail "checksums.txt not found" "Download checksums.txt with the archive and verify manually before installing."
    }
    $expected = Get-ChecksumEntry $ChecksumsPath $ArtifactName
    if (-not $expected) { Fail "no checksum entry found for $ArtifactName" "The release checksums.txt may not list this platform artifact yet." }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArtifactPath).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        Fail "checksum mismatch for $ArtifactName" @"
Expected: $expected
Got:      $actual
Refuse to install a corrupted or tampered archive.
"@
    }
}

# Returns $null when path is missing or not ryk; otherwise @{ Version = <semver or $null> }.
# Product detection uses the stable version --json contract, not the human banner.
function Get-ExistingProductInfo($Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $output = & $Path version --json 2>$null | Out-String
    } catch {
        return $null
    }
    if ($LASTEXITCODE -ne 0) { return $null }
    if (-not ($output -match '"product"\s*:\s*"ryk"')) {
        return $null
    }
    $version = $null
    $m = [regex]::Match($output, '\d+\.\d+\.\d+')
    if ($m.Success) { $version = $m.Value }
    return @{ Version = $version }
}

# Conservative product identity matching scripts/install.sh. Basename must be
# ryk/ryk.exe. Prefer a cheap marker so a broken product binary is still
# overwrite-safe; otherwise probe version --json.
function Test-IsRykProductBinary($Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) { return $false }
    if ($item.Name -ne "ryk" -and $item.Name -ne "ryk.exe") { return $false }
    try {
        $reader = [System.IO.StreamReader]::new($Path)
        try {
            $chunk = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
        if ($chunk -match '"product"\s*:\s*"ryk"' -or $chunk.Contains("safety_boundary_version")) {
            return $true
        }
    } catch {
        # Fall through to the version probe.
    }
    return $null -ne (Get-ExistingProductInfo $Path)
}

function Install-RuntimeAssets($ExtractRoot) {
    New-Item -ItemType Directory -Force -Path $ResourceRoot | Out-Null
    foreach ($dir in $RuntimeDirs) {
        $source = Join-Path $ExtractRoot $dir
        if (-not (Test-Path -LiteralPath $source)) {
            Fail "release archive missing runtime directory: $dir" "Re-download the official release artifact for v$Version."
        }
        $dest = Join-Path $ResourceRoot $dir
        if (Test-Path -LiteralPath $dest) {
            Remove-Item -LiteralPath $dest -Recurse -Force
        }
        Copy-Item -LiteralPath $source -Destination $dest -Recurse -Force
    }
    # Same marker contract as scripts/install.sh so `ryk uninstall` can recognize the runtime.
    $markerPath = Join-Path $ResourceRoot ".ryk-installation"
    $markerText = "ryk-runtime-v1`nversion=$Version`n"
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($markerPath, $markerText, $utf8NoBom)
    New-Item -ItemType Directory -Force -Path $ShareDir | Out-Null
    if (Test-Path -LiteralPath $CurrentLink) {
        Remove-Item -LiteralPath $CurrentLink -Recurse -Force -ErrorAction SilentlyContinue
    }
    cmd /c mklink /J "$CurrentLink" "$ResourceRoot"
    if ($LASTEXITCODE -ne 0) {
        Fail "failed to create junction $CurrentLink -> $ResourceRoot (mklink exit code $LASTEXITCODE)"
    }
}

function Ensure-ResourceRootEntry($TargetRoot) {
    $profilePath = if ($PROFILE) { $PROFILE } else { Join-Path $HOME "Documents\PowerShell\Microsoft.PowerShell_profile.ps1" }
    $marker = "# ryk runtime assets"
    $profileDir = Split-Path -Parent $profilePath
    if ($profileDir -and -not (Test-Path -LiteralPath $profileDir)) {
        New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
    }

    if ((Test-Path -LiteralPath $profilePath) -and (Select-String -LiteralPath $profilePath -Pattern [regex]::Escape($marker) -Quiet)) {
        $lines = Get-Content -LiteralPath $profilePath
        $updated = New-Object System.Collections.Generic.List[string]
        $skipNextResourceRoot = $false
        foreach ($line in $lines) {
            if ($line -eq $marker) {
                [void]$updated.Add($line)
                [void]$updated.Add("`$env:RYK_RESOURCE_ROOT = `"$TargetRoot`"")
                $skipNextResourceRoot = $true
                continue
            }
            if ($skipNextResourceRoot -and $line -match '^\$env:RYK_RESOURCE_ROOT\s*=') {
                continue
            }
            if ($skipNextResourceRoot -and [string]::IsNullOrWhiteSpace($line)) {
                $skipNextResourceRoot = $false
            }
            [void]$updated.Add($line)
        }
        Set-Content -LiteralPath $profilePath -Value $updated
        return
    }

    @(
        "",
        $marker,
        "`$env:RYK_RESOURCE_ROOT = `"$TargetRoot`""
    ) | Add-Content -LiteralPath $profilePath
}

function Invoke-InstallEnsure($Destination) {
    $oldResourceRoot = $env:RYK_RESOURCE_ROOT
    $oldPath = $env:PATH
    $oldNoColor = $env:NO_COLOR
    try {
        Push-Location -LiteralPath $HOME
        $env:RYK_RESOURCE_ROOT = $CurrentLink
        $env:PATH = "$InstallDir;$oldPath"
        $env:NO_COLOR = "1"
        & $Destination doctor --fix --from-install
        if ($LASTEXITCODE -ne 0) {
            Fail "ryk protection setup failed (exit code $LASTEXITCODE)" "Re-run from your home directory: ryk doctor --fix --from-install."
        }
    } finally {
        Pop-Location
        if ($null -eq $oldResourceRoot) { Remove-Item Env:RYK_RESOURCE_ROOT -ErrorAction SilentlyContinue } else { $env:RYK_RESOURCE_ROOT = $oldResourceRoot }
        if ($null -eq $oldPath) { Remove-Item Env:PATH -ErrorAction SilentlyContinue } else { $env:PATH = $oldPath }
        if ($null -eq $oldNoColor) { Remove-Item Env:NO_COLOR -ErrorAction SilentlyContinue } else { $env:NO_COLOR = $oldNoColor }
    }
}

function Write-SuccessReceipt {
    param(
        [string]$PreviousVersion
    )

    if ($Quiet) {
        return
    }

    Write-Host ""
    if ($PreviousVersion -and $PreviousVersion -ne $Version -and $PreviousVersion -ne "installed") {
        Write-Ui ("  +  ryk v" + $Version + " installed  (upgraded from " + $PreviousVersion + ")") Green
    } elseif ($PreviousVersion) {
        Write-Ui ("  +  ryk v" + $Version + " reinstalled") Green
    } else {
        Write-Ui ("  +  ryk v" + $Version + " installed") Green
    }
    Write-Host ""
    Write-HostHint
    Write-Host ""
}

$os = Detect-OS
$arch = Detect-Arch
if ($os -ne "windows") { Fail "unsupported operating system: $os" }

$artifact = "ryk-v$Version-windows-$arch.zip"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "ryk-install-$([System.Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempDir | Out-Null

$destination = Join-Path $InstallDir "ryk.exe"

# Empty = fresh; semver or "installed" = existing CLI at destination.
$previousVersion = $null
$existingCli = Get-ExistingProductInfo $destination
if ($existingCli) {
    $previousVersion = $existingCli.Version
    if (-not $previousVersion) { $previousVersion = "installed" }
}

if (-not $Quiet) {
    Write-Host ""
    Write-Ui ("  ryk · v" + $Version) Cyan
    Write-Ui "  --------------------------------" DarkGray
    Write-Ui "  Agent runtime protection · policy + shell_engine" DarkGray
    Write-Host ("  Platform  " + $os + "/" + $arch)
    Write-Host ("  Target    " + $InstallDir)
    Write-Host ""
}

try {
    $artifactPath = Join-Path $tempDir $artifact
    $checksumsPath = Join-Path $tempDir "checksums.txt"

    $resolveDetail = "v" + $Version
    if ($previousVersion -and $previousVersion -ne $Version -and $previousVersion -ne "installed") {
        $resolveDetail = $resolveDetail + "; upgrading " + $previousVersion + " -> " + $Version
    } elseif ($previousVersion) {
        $resolveDetail = $resolveDetail + "; reinstall"
    }
    Write-StepDone "Resolve release" $resolveDetail

    if ($ArtifactDir) {
        $localArtifact = Join-Path $ArtifactDir $artifact
        $localChecksums = Join-Path $ArtifactDir "checksums.txt"
        if (-not (Test-Path -LiteralPath $localArtifact)) {
            Fail "artifact not found: $artifact under RYK_ARTIFACT_DIR."
        }
        if (-not (Test-Path -LiteralPath $localChecksums)) {
            Fail "checksums.txt not found in $ArtifactDir" "Place checksums.txt next to the archive for offline install."
        }
        Copy-Item -LiteralPath $localArtifact -Destination $artifactPath
        Copy-Item -LiteralPath $localChecksums -Destination $checksumsPath
        Write-StepDone "Use local artifacts" $ArtifactDir
    } else {
        Write-StepActive "Download archive"
        Invoke-WebRequest -Uri "$BaseUrl/$artifact" -OutFile $artifactPath
        Invoke-WebRequest -Uri "$BaseUrl/checksums.txt" -OutFile $checksumsPath
        Write-StepDone "Download archive" $artifact
    }

    Verify-Checksum $artifactPath $checksumsPath $artifact
    Write-StepDone "Verify SHA-256" "ok"

    Write-StepActive "Install binaries + runtime"
    Expand-Archive -LiteralPath $artifactPath -DestinationPath $tempDir -Force
    $extractRoot = Get-ChildItem -LiteralPath $tempDir -Directory | Where-Object { $_.Name -eq "ryk-v$Version-windows-$arch" } | Select-Object -First 1
    if (-not $extractRoot) {
        Fail "artifact did not contain an extracted release root" "Unexpected archive layout for $artifact."
    }
    $binaryPath = Join-Path $extractRoot.FullName "bin\ryk.exe"
    $binary = if (Test-Path -LiteralPath $binaryPath) { Get-Item -LiteralPath $binaryPath } else { $null }
    if (-not $binary) {
        Fail "artifact did not contain bin\ryk.exe" "Unexpected archive layout for $artifact."
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $force = $env:RYK_INSTALL_FORCE -eq "1"
    if (Test-Path -LiteralPath $destination) {
        $destItem = Get-Item -LiteralPath $destination -Force
        if ($destItem.PSIsContainer) {
            Fail "refusing directory binary destination path: $destination" "Choose a path whose final target is a regular file or an existing ryk symlink."
        }
        if (-not $force -and -not (Test-IsRykProductBinary $destination)) {
            Fail "refusing to overwrite non-ryk file at $destination" "ryk update --force"
        }
    }
    Copy-Item -LiteralPath $binary.FullName -Destination $destination -Force
    $canonicalDestination = [System.IO.Path]::GetFullPath($destination)
    $binaryDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLowerInvariant()
    $provenanceStage = Join-Path $InstallDir (".ryk-provenance." + [Guid]::NewGuid().ToString("N") + ".tmp")
    @(
        "ryk-provenance-v1",
        "path=$canonicalDestination",
        "sha256=$binaryDigest"
    ) | Set-Content -LiteralPath $provenanceStage -Encoding utf8NoBOM
    Move-Item -LiteralPath $provenanceStage -Destination (Join-Path $InstallDir ".ryk-provenance") -Force
    Install-RuntimeAssets $extractRoot.FullName
    Write-StepDone "Install binaries + runtime" "ryk.exe + assets (CLI-only; shell_engine in-process)"

    Ensure-ResourceRootEntry $CurrentLink
    Write-StepDone "Configure shell" "RYK_RESOURCE_ROOT (share path unchanged in 5a)"

    Write-StepActive "Set up protection"
    Invoke-InstallEnsure $destination
    Write-StepDone "Set up protection" "doctor --fix --from-install"

    Write-SuccessReceipt -PreviousVersion $previousVersion
} finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
