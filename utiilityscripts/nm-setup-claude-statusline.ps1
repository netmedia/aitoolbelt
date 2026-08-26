#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the Netmedia powerline status line for Claude Code.

.DESCRIPTION
    Writes statusline.ps1 to ~/.claude/ and merges the statusLine entry
    into ~/.claude/settings.json. Safe to run multiple times.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Paths ──────────────────────────────────────────────────────────────────────
$claudeDir      = Join-Path $HOME '.claude'
$settingsFile   = Join-Path $claudeDir 'settings.json'
$statuslineFile = Join-Path $claudeDir 'statusline.ps1'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step([string]$msg) { Write-Host "  $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "  v $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }

function ConvertTo-Hashtable {
    param([Parameter(ValueFromPipeline)] $InputObject)
    process {
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $collection = @()
            foreach ($item in $InputObject) { $collection += ConvertTo-Hashtable $item }
            return ,$collection
        }
        if ($InputObject -is [psobject]) {
            $hash = @{}
            foreach ($prop in $InputObject.PSObject.Properties) {
                $hash[$prop.Name] = ConvertTo-Hashtable $prop.Value
            }
            return $hash
        }
        return $InputObject
    }
}

Write-Host ""
Write-Host "Claude Code - Calvados powerline status line setup" -ForegroundColor White
Write-Host ("-" * 51) -ForegroundColor DarkGray
Write-Host ""

# 1. Ensure ~/.claude exists
if (-not (Test-Path $claudeDir)) {
    Write-Step "Creating $claudeDir ..."
    New-Item -ItemType Directory -Path $claudeDir | Out-Null
}

# 2. Write statusline.ps1
Write-Step "Writing statusline.ps1 ..."
$statuslineContent = @'
$input_data = $input | ConvertFrom-Json

# --- Section 1: last 2 folders of cwd (or project root if in a worktree) ---
$cwd = $input_data.cwd
if (-not $cwd) { $cwd = $input_data.workspace.current_dir }
$cwd = $cwd -replace '\\','/'

# If inside a worktree, use the project root path instead
$worktreeMarker = '/.claude/worktrees/'
$markerIdx = $cwd.IndexOf($worktreeMarker)
if ($markerIdx -ge 0) {
    $basePath = $cwd.Substring(0, $markerIdx)
} else {
    $basePath = $cwd.TrimEnd('/')
}

$parts = $basePath -split '/'
$parts = $parts | Where-Object { $_ -ne '' }
if ($parts.Count -ge 2) {
    $pathDisplay = "$($parts[-2])/$($parts[-1])"
} elseif ($parts.Count -eq 1) {
    $pathDisplay = $parts[-1]
} else {
    $pathDisplay = $basePath
}

# --- Section 2: worktree name ---
$worktreeName = $input_data.worktree.name
if ($worktreeName) {
    $worktreeDisplay = $worktreeName
} else {
    $worktreeDisplay = '--none--'
}

# --- Section 3: context bar ---
$usedPct = $input_data.context_window.used_percentage
$hasContext = ($null -ne $usedPct)
if ($hasContext) {
    $pctInt = [math]::Round($usedPct)
    $filled = [math]::Round($pctInt * 10 / 100)
    $empty  = 10 - $filled
    $bar    = ([char]0x2588 * $filled) + ([char]0x2591 * $empty)
    $barDisplay = "$bar $pctInt%"
} else {
    $pctInt = 0
    $barDisplay = ([char]0x2591 * 10) + ' --%'
}

# --- Section 4: daily token usage ---
$totalIn  = $input_data.context_window.total_input_tokens
$totalOut = $input_data.context_window.total_output_tokens
$totalTokens = 0
if ($null -ne $totalIn)  { $totalTokens += $totalIn }
if ($null -ne $totalOut) { $totalTokens += $totalOut }

function Format-TokenCount([long]$n) {
    if ($n -ge 1000000) { return "{0:0.0}M" -f ($n / 1000000) }
    if ($n -ge 1000)    { return "{0:0.0}k" -f ($n / 1000) }
    return "$n"
}
$tokenStr = Format-TokenCount $totalTokens

$fiveHourPct      = $input_data.rate_limits.five_hour.used_percentage
$fiveHourResetsAt = $input_data.rate_limits.five_hour.resets_at
$hasRateLimit = ($null -ne $fiveHourPct)
if ($hasRateLimit) {
    $ratePctInt = [math]::Round($fiveHourPct)
    $rateFilled = [math]::Round($ratePctInt * 8 / 100)
    $rateEmpty  = 8 - $rateFilled
    $rateBar    = ([char]0x2588 * $rateFilled) + ([char]0x2591 * $rateEmpty)

    # Countdown timer from resets_at (Unix epoch seconds)
    $countdownStr = ''
    if ($null -ne $fiveHourResetsAt) {
        $nowEpoch    = [long](([DateTimeOffset]::UtcNow).ToUnixTimeSeconds())
        $secsLeft    = [long]$fiveHourResetsAt - $nowEpoch
        if ($secsLeft -gt 0) {
            $hLeft = [math]::Floor($secsLeft / 3600)
            $mLeft = [math]::Floor(($secsLeft % 3600) / 60)
            if ($hLeft -gt 0) {
                $countdownStr = " ${hLeft}h ${mLeft}m left"
            } else {
                $countdownStr = " ${mLeft}m left"
            }
        } else {
            $countdownStr = ' resetting'
        }
    }

    $tokenCoreDisplay = "$tokenStr  $rateBar $ratePctInt%"
    $hoursDisplay     = $countdownStr.TrimStart()
} else {
    $ratePctInt       = 0
    $tokenCoreDisplay = "$tokenStr"
    $hoursDisplay     = ''
}

# ANSI helpers
$e = [char]27
# 256-color backgrounds (80s retro, softer)
$bgNavy    = "$e[48;5;125m"  # Block 1: muted raspberry/pink
$bgMagenta = "$e[48;5;31m"   # Block 2: muted teal
$bgGreen   = "$e[48;5;64m"   # Block 3: muted olive green (<50%)
$bgOrange  = "$e[48;5;166m"  # Block 3: muted burnt orange (50-79%)
$bgRed     = "$e[48;5;124m"  # Block 3: muted dark red    (>=80%)
$bgDark    = "$e[48;5;236m"  # Block 3: dark grey         (no data)
$bgPurple  = "$e[48;5;54m"   # Block 4: muted deep purple (token usage, low)
$bgViolet  = "$e[48;5;91m"   # Block 4: medium violet     (token usage, mid)
$bgCrimson = "$e[48;5;88m"   # Block 4: dark crimson      (token usage, high)
$bgHoursLow  = "$e[48;5;60m"   # Block 5: soft slate blue   (hours, low)
$bgHoursMid  = "$e[48;5;97m"   # Block 5: soft muted purple (hours, mid)
$bgHoursHigh = "$e[48;5;131m"  # Block 5: soft muted rose   (hours, high)
# 256-color foregrounds matching each background (for powerline arrows)
$fgNavy    = "$e[38;5;125m"
$fgMagenta = "$e[38;5;31m"
$fgGreen   = "$e[38;5;64m"
$fgOrange  = "$e[38;5;166m"
$fgRed     = "$e[38;5;124m"
$fgDarkGrey= "$e[38;5;236m"
$fgPurple  = "$e[38;5;54m"
$fgViolet  = "$e[38;5;91m"
$fgCrimson = "$e[38;5;88m"
$fgHoursLow  = "$e[38;5;60m"
$fgHoursMid  = "$e[38;5;97m"
$fgHoursHigh = "$e[38;5;131m"
# General foregrounds
$fgWhite   = "$e[97m"
$reset     = "$e[0m"

# Powerline arrow
$arrow = [char]0xE0B0

# Pick context bar colors
if ($hasContext) {
    if ($pctInt -lt 50) {
        $barBg = $bgGreen;  $barFg = $fgWhite; $s2ToS3Fg = $fgGreen
    } elseif ($pctInt -lt 80) {
        $barBg = $bgOrange; $barFg = $fgWhite; $s2ToS3Fg = $fgOrange
    } else {
        $barBg = $bgRed;    $barFg = $fgWhite; $s2ToS3Fg = $fgRed
    }
} else {
    $barBg = $bgDark; $barFg = $fgWhite; $s2ToS3Fg = $fgDarkGrey
}

# Pick token section colors (based on rate limit % when available, else always purple)
if ($hasRateLimit) {
    if ($ratePctInt -lt 50) {
        $tokenBg = $bgPurple;  $s3ToS4Fg = $fgPurple;  $hoursBg = $bgHoursLow;  $s4ToS5Fg = $fgHoursLow
    } elseif ($ratePctInt -lt 80) {
        $tokenBg = $bgViolet;  $s3ToS4Fg = $fgViolet;  $hoursBg = $bgHoursMid;  $s4ToS5Fg = $fgHoursMid
    } else {
        $tokenBg = $bgCrimson; $s3ToS4Fg = $fgCrimson; $hoursBg = $bgHoursHigh; $s4ToS5Fg = $fgHoursHigh
    }
} else {
    $tokenBg = $bgPurple; $s3ToS4Fg = $fgPurple; $hoursBg = $bgHoursLow; $s4ToS5Fg = $fgHoursLow
}

# Build output:
#   [navy bg]    path         [magenta arrow]
#   [magenta bg] worktree    [bar-color arrow]
#   [bar bg]     ctx bar     [token-color arrow]
#   [token bg]   token+bar   [hours-color arrow]
#   [hours bg]   countdown   [reset]
$out  = "${bgNavy}${fgWhite} ${pathDisplay} "
$out += "${bgMagenta}${fgNavy}${arrow}"         # S1->S2: navy-colored arrow on magenta bg
$out += "${fgWhite} ${worktreeDisplay} "
$out += "${barBg}${s2ToS3Fg}${arrow}"           # S2->S3: bar-color arrow on bar bg
$out += "${fgWhite} ${barDisplay} "
$out += "${tokenBg}${s3ToS4Fg}${arrow}"         # S3->S4: token-color arrow on token bg
$out += "${fgWhite} ${tokenCoreDisplay} "
if ($hoursDisplay -ne '') {
    $out += "${hoursBg}${s4ToS5Fg}${arrow}"     # S4->S5: hours-color arrow on hours bg
    $out += "${fgWhite} ${hoursDisplay} "
}
$out += $reset

Write-Host -NoNewline $out
'@

[System.IO.File]::WriteAllText($statuslineFile, $statuslineContent, [System.Text.UTF8Encoding]::new($false))
Write-Ok "Saved: $statuslineFile"

# 3. Load or initialize settings.json
if (Test-Path $settingsFile) {
    Write-Step "Loading existing settings.json ..."
    $raw = Get-Content $settingsFile -Raw -Encoding UTF8
    try {
        $settings = $raw | ConvertFrom-Json | ConvertTo-Hashtable
    } catch {
        Write-Warn "settings.json exists but could not be parsed. Aborting to avoid data loss."
        Write-Warn "Fix the file manually, then re-run this script."
        Write-Host ""
        exit 1
    }
} else {
    Write-Step "No settings.json found - will create one ..."
    $settings = @{}
}

# 4. Merge statusLine entry
$statusLineValue = @{
    type    = 'command'
    command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$statuslineFile`""
}

$existing = $settings['statusLine']
if ($existing -and $existing['command'] -eq $statusLineValue['command']) {
    Write-Ok "statusLine already configured - skipping"
} else {
    $settings['statusLine'] = $statusLineValue
    Write-Step "Writing settings.json ..."
    $json = $settings | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($settingsFile, $json, [System.Text.UTF8Encoding]::new($false))
    Write-Ok "Saved: $settingsFile"
}

Write-Host ""
Write-Host "Done! Start a new Claude Code session to activate the status line." -ForegroundColor White
Write-Host ""
Write-Host "What you get:" -ForegroundColor DarkGray
Write-Host "  [path]  [worktree]  [context bar]  [tokens + rate limit]  [reset countdown]" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Tip: if blocked by execution policy, run with:" -ForegroundColor DarkGray
Write-Host "  powershell -ExecutionPolicy Bypass -File .\nm-setup-statusline.ps1" -ForegroundColor Yellow
Write-Host ""
