param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Targets
)

$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$OutputDir = if ($env:OUTPUT_DIR) { $env:OUTPUT_DIR } else { Join-Path $RootDir "dist/go" }

$DefaultTargets = @(
    "linux/amd64",
    "linux/arm64",
    "darwin/amd64",
    "darwin/arm64",
    "windows/amd64",
    "windows/arm64"
)

$Apps = @(
    @{ ModuleDir = "agents/device-client"; PackagePath = "./cmd/keyward-agent"; BinaryName = "keyward-agent" },
    @{ ModuleDir = "agents/device-client"; PackagePath = "./cmd/keyward-tray"; BinaryName = "keyward-tray" },
    @{ ModuleDir = "agents/server-agent"; PackagePath = "./cmd/keyward-server-agent"; BinaryName = "keyward-server-agent" }
)

function Show-Usage {
    @"
usage: scripts/build-go.ps1 [os/arch ...]

Builds all Go binaries for the provided targets.

Examples:
  pwsh ./scripts/build-go.ps1
  pwsh ./scripts/build-go.ps1 linux/amd64 darwin/arm64

Environment:
  OUTPUT_DIR   Override output directory (default: dist/go)
"@
}

if ($Targets.Count -gt 0 -and ($Targets[0] -eq "-h" -or $Targets[0] -eq "--help")) {
    Show-Usage
    exit 0
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "go is not installed or not in PATH"
}

if (-not $Targets -or $Targets.Count -eq 0) {
    $Targets = $DefaultTargets
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

if ($Targets -contains "windows/amd64") {
    $resourceScript = Join-Path $RootDir "scripts/generate-windows-resources.sh"
    if (Get-Command bash -ErrorAction SilentlyContinue) {
        & bash $resourceScript
    }
    else {
        Write-Warning "bash is not available; skipping Windows resource generation"
    }
}

foreach ($target in $Targets) {
    if ($target -notmatch "^([^/]+)/([^/]+)$") {
        throw "invalid target '$target' (expected os/arch)"
    }

    $goos = $Matches[1]
    $goarch = $Matches[2]
    $targetDir = Join-Path $OutputDir "$goos-$goarch"
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null

    foreach ($app in $Apps) {
        $suffix = if ($goos -eq "windows") { ".exe" } else { "" }
        $binaryPath = Join-Path $targetDir ($app.BinaryName + $suffix)
        $buildArgs = @("build", "-trimpath", "-buildvcs=false")

        if ($goos -eq "windows" -and $app.BinaryName -eq "keyward-tray") {
            $buildArgs += "-ldflags=-H=windowsgui"
        }

        $buildArgs += @("-o", $binaryPath, $app.PackagePath)

        Write-Host "==> $($app.BinaryName) for $goos/$goarch"
        Push-Location (Join-Path $RootDir $app.ModuleDir)
        try {
            $env:CGO_ENABLED = "0"
            $env:GOOS = $goos
            $env:GOARCH = $goarch
            & go @buildArgs

            if ($goos -eq "windows" -and $app.BinaryName -eq "keyward-tray") {
                Copy-Item (Join-Path $RootDir (Join-Path $app.ModuleDir "cmd/keyward-tray/keyward-tray.exe.manifest")) (Join-Path $targetDir "keyward-tray.exe.manifest") -Force
            }
        }
        finally {
            Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
            Remove-Item Env:GOOS -ErrorAction SilentlyContinue
            Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
            Pop-Location
        }
    }
}

Write-Host ""
Write-Host "Build artifacts written to $OutputDir"
