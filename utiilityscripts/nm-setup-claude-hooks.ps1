#Requires -Version 5.1
<#
.SYNOPSIS
    Configures Claude Code hooks so the Windows Terminal tab pulses orange
    when Claude is waiting for your input.

.DESCRIPTION
    Merges Stop / PreToolUse hooks into ~/.claude/settings.json.
    Existing settings are preserved. Safe to run multiple times.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Paths ──────────────────────────────────────────────────────────────────────
$claudeDir      = Join-Path $HOME '.claude'
$settingsFile   = Join-Path $claudeDir 'settings.json'

# ── Hook definitions ──────────────────────────────────────────────────────────
#    OSC 9;4 sequences – Windows Terminal tab state indicator
#    State 3 = "attention" (pulsing orange)   State 0 = clear
$hooksToAdd = @{
    Stop = @(
        @{
            matcher = ''
            hooks   = @(
                @{
                    type    = 'command'
                    # Set tab to pulsing orange + flash taskbar
                    command = 'powershell -NoProfile -Command "[Console]::Write([char]27 + '']9;4;3'' + [char]7); [Console]::Beep()" 2>/dev/null'
                }
            )
        }
    )
    PreToolUse = @(
        @{
            matcher = ''
            hooks   = @(
                @{
                    type    = 'command'
                    # Clear tab indicator the moment Claude starts working
                    command = 'powershell -NoProfile -Command "[Console]::Write([char]27 + '']9;4;0'' + [char]7)" 2>/dev/null'
                }
            )
        }
    )
}

# ── Helpers ───────────────────────────────────────────────────────────────────
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

function Write-Step([string]$msg) {
    Write-Host "  $msg" -ForegroundColor Cyan
}
function Write-Ok([string]$msg) {
    Write-Host "  ✓ $msg" -ForegroundColor Green
}
function Write-Warn([string]$msg) {
    Write-Host "  ⚠ $msg" -ForegroundColor Yellow
}

# ── Main ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Claude Code – Windows Terminal attention hooks setup" -ForegroundColor White
Write-Host ("─" * 52) -ForegroundColor DarkGray
Write-Host ""

# 1. Ensure ~/.claude exists
if (-not (Test-Path $claudeDir)) {
    Write-Step "Creating $claudeDir ..."
    New-Item -ItemType Directory -Path $claudeDir | Out-Null
}

# 2. Load or initialize settings.json
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
    Write-Step "No settings.json found – will create one ..."
    $settings = @{}
}

# 3. Ensure 'hooks' key exists
if (-not $settings.ContainsKey('hooks')) {
    $settings['hooks'] = @{}
}

# 4. Merge each hook event
$changed = $false
foreach ($event in $hooksToAdd.Keys) {
    $newEntry   = $hooksToAdd[$event][0]          # the matcher-wrapper object
    $newCmd     = $newEntry.hooks[0].command      # the inner command string

    if (-not $settings['hooks'].ContainsKey($event)) {
        # Event not present at all – add it
        $settings['hooks'][$event] = $hooksToAdd[$event]
        Write-Ok "Added $event hook"
        $changed = $true
    } else {
        # Event already has entries – check if our command is already present
        # inside any matcher entry's hooks array
        $existing = $settings['hooks'][$event]
        $alreadyPresent = $false
        foreach ($entry in $existing) {
            if ($entry -is [hashtable] -and $entry.ContainsKey('hooks')) {
                foreach ($h in $entry['hooks']) {
                    if ($h['type'] -eq 'command' -and $h['command'] -eq $newCmd) {
                        $alreadyPresent = $true
                    }
                }
            }
        }

        if ($alreadyPresent) {
            Write-Ok "$event hook already configured – skipping"
        } else {
            # Append our matcher entry without removing existing ones
            $settings['hooks'][$event] = @($existing) + $hooksToAdd[$event]
            Write-Ok "Appended to existing $event hooks"
            $changed = $true
        }
    }
}

# 5. Write back if anything changed
if ($changed) {
    Write-Step "Writing settings.json ..."
    $json = $settings | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($settingsFile, $json, [System.Text.UTF8Encoding]::new($false))
    Write-Ok "Saved: $settingsFile"
} else {
    Write-Ok "Nothing to change – settings.json already up to date"
}

Write-Host ""
Write-Host "Done! Start a new Claude Code session to activate the hooks." -ForegroundColor White
Write-Host ""
Write-Host "What to expect:" -ForegroundColor DarkGray
Write-Host "  • Tab pulses orange  →  Claude is waiting for your input"  -ForegroundColor DarkGray
Write-Host "  • Tab returns normal →  Claude started working on your reply" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Tip: if the script didn't run and you got a security/execution policy error," -ForegroundColor DarkGray
Write-Host "run it like this instead:" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  powershell -ExecutionPolicy Bypass -File .\nm-setup-claude-hooks.ps1" -ForegroundColor Yellow
Write-Host ""
