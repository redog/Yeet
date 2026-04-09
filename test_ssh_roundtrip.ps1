#Requires -Modules Microsoft.PowerShell.Utility, Microsoft.PowerShell.Management
#Requires -Version 5.1

<#
.SYNOPSIS
Tests that Yeet.ps1 upload+get preserves SSH key content exactly.

.DESCRIPTION
Generates a fresh ed25519 key pair, uploads it to Bitwarden via Yeet.ps1 upload,
retrieves it via Yeet.ps1 get, then verifies the retrieved file is byte-for-byte
identical to the line-ending-normalised original (no extra newlines, no \r).

.EXAMPLE
.\test_ssh_roundtrip.ps1

.NOTES
Requires: bw (logged in & unlocked), ssh-keygen, pwsh (PowerShell 7+)
#>

$ErrorActionPreference = 'Stop'
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$YeetPs1     = Join-Path $ScriptDir "Yeet.ps1"
$TempDir     = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
$Timestamp   = Get-Date -Format 'yyyyMMddHHmmss'
$TestKeyName = "yeet-test-$Timestamp"
$SshDir      = Join-Path $HOME ".ssh"
$script:Pass = $true

# ── helpers ───────────────────────────────────────────────────────────────────

function Write-Ok   { param($m) Write-Host "    PASS: $m" -ForegroundColor Green }
function Write-Fail { param($m) Write-Host "    FAIL: $m" -ForegroundColor Red; $script:Pass = $false }
function Write-Step { param($n, $m) Write-Host "`n[$n] $m" }

function Get-Sha256File {
    param([string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

function Get-Sha256String {
    param([string]$Content)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    return ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
}

# Applies the same normalisation that Yeet.ps1 upload uses before storing in Bitwarden:
# strip \r, trim trailing whitespace/newlines, append exactly one \n.
function Get-NormalisedKey {
    param([string]$Path)
    $raw = [System.IO.File]::ReadAllText($Path)
    return ($raw -replace "`r", "").TrimEnd() + "`n"
}

# ── cleanup ───────────────────────────────────────────────────────────────────

function Invoke-Cleanup {
    Write-Host "`n=== Cleanup ==="
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $SshDir $TestKeyName) -Force -ErrorAction SilentlyContinue
    foreach ($f in @('yeet_test_in.txt','yeet_get_out.txt','yeet_get_err.txt')) {
        Remove-Item -Path "$env:TEMP\$f" -Force -ErrorAction SilentlyContinue
    }

    try {
        $items = bw list items 2>$null | ConvertFrom-Json -ErrorAction Stop
        $item  = $items | Where-Object { $_.type -eq 5 -and $_.name -eq $TestKeyName } | Select-Object -First 1
        if ($item) {
            bw delete item $item.id | Out-Null
            Write-Host "  Removed '$TestKeyName' from Bitwarden."
        }
    } catch {
        Write-Warning "Could not remove '$TestKeyName' from Bitwarden — remove it manually."
    }
}

# ── main ──────────────────────────────────────────────────────────────────────

try {
    New-Item -ItemType Directory -Path $TempDir | Out-Null

    Write-Host "=== Yeet.ps1 SSH Key Roundtrip Test ==="
    Write-Host "    Key name : $TestKeyName"
    Write-Host "    Temp dir : $TempDir"

    # Prerequisites
    foreach ($cmd in @('bw', 'ssh-keygen')) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            throw "'$cmd' not found in PATH."
        }
    }
    $bwStatus = bw status 2>$null | ConvertFrom-Json -ErrorAction Stop
    if ($bwStatus.status -ne 'unlocked') {
        throw "Bitwarden vault is not unlocked. Run 'bw login' or 'bw unlock' first."
    }

    # ── Step 1: Generate a fresh ed25519 key pair ─────────────────────────────
    Write-Step 1 "Generating test ed25519 key pair..."
    $origPriv = Join-Path $TempDir $TestKeyName
    $origPub  = "$origPriv.pub"

    ssh-keygen -t ed25519 -f $origPriv -q -N '' -C $TestKeyName
    if ($LASTEXITCODE -ne 0) { throw "ssh-keygen failed (exit $LASTEXITCODE)" }

    $origPrivSha  = Get-Sha256File $origPriv
    $origPrivSize = (Get-Item $origPriv).Length
    Write-Host "    Private : $origPrivSize bytes  SHA256=$origPrivSha"
    Write-Host "    Public  : $((Get-Item $origPub).Length) bytes  SHA256=$(Get-Sha256File $origPub)"

    # ── Step 2: Upload via Yeet.ps1 ───────────────────────────────────────────
    Write-Step 2 "Uploading to Bitwarden via Yeet.ps1 upload..."
    & pwsh $YeetPs1 upload $origPriv $TestKeyName
    if ($LASTEXITCODE -ne 0) { throw "Yeet.ps1 upload failed (exit $LASTEXITCODE)" }
    Write-Host "    Upload complete."

    # ── Step 3: Get via Yeet.ps1 ─────────────────────────────────────────────
    # The get command writes the private key then calls Read-Host for the
    # authorized_keys prompt. When pwsh is launched with stdin redirected to a
    # file (non-interactive), Read-Host reads from that file in PowerShell 7+.
    Write-Step 3 "Downloading from Bitwarden via Yeet.ps1 get..."

    $inFile  = "$env:TEMP\yeet_test_in.txt"
    $outFile = "$env:TEMP\yeet_get_out.txt"
    $errFile = "$env:TEMP\yeet_get_err.txt"
    [System.IO.File]::WriteAllText($inFile, "n`n")   # answer 'n' to authorized_keys prompt

    $proc = Start-Process -FilePath "pwsh" `
        -ArgumentList @("-File", $YeetPs1, "get", $TestKeyName) `
        -RedirectStandardInput  $inFile `
        -RedirectStandardOutput $outFile `
        -RedirectStandardError  $errFile `
        -Wait -PassThru -NoNewWindow

    if (Test-Path $outFile) { Get-Content $outFile | ForEach-Object { Write-Host "    $_" } }

    $retrievedPath = Join-Path $SshDir $TestKeyName
    if (-not (Test-Path $retrievedPath)) {
        if (Test-Path $errFile) { Get-Content $errFile | ForEach-Object { Write-Host "    [err] $_" } }
        throw "Yeet.ps1 get did not create the key file at '$retrievedPath'"
    }
    Write-Host "    Download complete -> $retrievedPath"

    # ── Step 4: Compare ───────────────────────────────────────────────────────
    Write-Step 4 "Comparing original vs retrieved private key..."

    # Expected: content after upload normalisation (strip \r, TrimEnd, + one \n)
    $normContent = Get-NormalisedKey $origPriv
    $normSha     = Get-Sha256String  $normContent
    $normBytes   = [System.Text.Encoding]::UTF8.GetByteCount($normContent)

    $retrSha     = Get-Sha256File $retrievedPath
    $retrBytes   = (Get-Item $retrievedPath).Length
    $retrContent = [System.IO.File]::ReadAllText($retrievedPath)

    Write-Host "    Original  : $origPrivSize bytes  SHA256=$origPrivSha"
    Write-Host "    Normalised: $normBytes bytes  SHA256=$normSha  (expected after upload)"
    Write-Host "    Retrieved : $retrBytes bytes  SHA256=$retrSha"

    # Check 1: byte-for-byte match with normalised original
    if ($retrSha -eq $normSha) {
        Write-Ok "Retrieved key matches normalised original exactly."
    } else {
        Write-Fail "Retrieved key does NOT match normalised original."
        $retrByteArr = [System.IO.File]::ReadAllBytes($retrievedPath)
        $tail = ($retrByteArr | Select-Object -Last 10 | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' '
        Write-Host "    Tail bytes (retrieved): $tail"
    }

    # Check 2: no \r characters
    if ($retrContent -notmatch "`r") {
        Write-Ok "No carriage-return (\`r) characters in retrieved key."
    } else {
        Write-Fail "Retrieved key contains carriage-return (\`r) characters."
    }

    # Check 3: exactly one trailing LF (0x0A)
    $retrByteArr = [System.IO.File]::ReadAllBytes($retrievedPath)
    $trailingLF  = 0
    for ($i = $retrByteArr.Length - 1; $i -ge 0; $i--) {
        if ($retrByteArr[$i] -eq 0x0A) { $trailingLF++ } else { break }
    }
    if ($trailingLF -eq 1) {
        Write-Ok "Retrieved key ends with exactly one newline (0x0A)."
    } else {
        Write-Fail "Retrieved key has $trailingLF trailing newline byte(s) — expected 1."
    }

    # Check 4: ssh-keygen can parse the retrieved key (not corrupted)
    $fp = ssh-keygen -lf $retrievedPath 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Retrieved private key is valid: $fp"
    } else {
        Write-Fail "ssh-keygen cannot parse retrieved key: $fp"
    }

} finally {
    Invoke-Cleanup
}

Write-Host ""
if ($script:Pass) {
    Write-Host "=== ALL CHECKS PASSED ===" -ForegroundColor Green
    exit 0
} else {
    Write-Host "=== ONE OR MORE CHECKS FAILED ===" -ForegroundColor Red
    exit 1
}
