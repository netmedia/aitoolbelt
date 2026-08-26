#Requires -Version 5.1

#  ╔══════════════════════════════════════════════════════════════════════════╗
#  ║   nm-reopen-worktrees.ps1                                                ║
#  ║                                                                          ║
#  ║   Author  : Netmedia                                                     ║
#  ║   Web     : https://netmedia.agency                                      ║
#  ║   Email   : netmedia@netmedia.hr                                         ║
#  ╚══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    Reopens all git worktrees in Windows Terminal tabs and resumes Claude Code in each.

.AUTHOR
    Netmedia  |  https://netmedia.agency  |  netmedia@netmedia.hr

.DESCRIPTION
    After a terminal close, hibernation, or system crash, this script restores
    your working layout by opening one Windows Terminal tab per git worktree and
    auto-resuming the most recent Claude Code session inside each.

    Useful when:
      - The laptop hibernated/crashed with multiple worktrees and Claude Code
        sessions open and you need to pick up where you left off.
      - You finished a planning session in plan mode and want to resume
        implementation later in a fresh terminal.
      - You want a one-shot way to reopen a familiar multi-worktree setup.

.PARAMETER RepoPath
    (Required) Path to any worktree of the repository (typically the main one).
    Used to discover all worktrees via  git worktree list.  Accepts absolute or
    relative paths.

.PARAMETER IncludeMain
    Also open a tab for the main worktree.  Off by default — feature/planning
    work usually happens in feature worktrees branched off develop or main, and
    the main worktree is rarely an active Claude Code session.

.PARAMETER UseResume
    Use  claude --resume  (interactive picker) instead of  claude --continue
    (most recent session).  Use this when the session you want to resume is not
    the most recent session in a given worktree — Claude will show a picker in
    each tab so you can choose.

.PARAMETER Select
    Show a numbered list of all worktrees and prompt for which ones to open.
    Accepts single numbers, ranges, and combinations:
        1,3,5      — pick #1, #3, #5
        1-3        — pick range #1 through #3
        1,3-5,8    — pick #1, #3 through #5, and #8
        a / all    — select all (Enter also = all)
        n / none   — cancel without opening anything
    When -Select is given, -IncludeMain is implied (main is in the list).

.PARAMETER DryRun
    List the worktrees that would be opened without launching Windows Terminal.
    Combine with -Select to interactively pick and verify before launching.
    In -Cleanup mode, previews all removal actions without touching anything.

.PARAMETER Cleanup
    Enter cleanup mode: interactively pick worktrees to REMOVE.

    Flow:
      1. Pick worktrees from the numbered list (default: none).
      2. Script builds a plan (checks dirty state, remote branch existence).
      3. Displays the complete plan + a destructive-actions summary.
      4. Requires typing YES (uppercase, exact) to proceed.  Anything else cancels.
      5. Executes: git worktree remove, git branch -D, and (if requested) git
         push --delete on origin.  Runs  git worktree prune  at the end.

    Skip rules (worktrees remain untouched):
      - The main worktree is always skipped.
      - Dirty worktrees are skipped unless -Force is set.

.PARAMETER CleanupRemote
    Only meaningful with -Cleanup.  Also deletes branches on origin when they
    exist there.  Without this flag, remote branches are kept untouched.

.PARAMETER Force
    Skip the YES confirmation gate in -Cleanup mode.  Also allows removal of
    worktrees with uncommitted changes (git worktree remove --force + branch -D).
    Use only when scripting non-interactively — accidental use loses work.

.PARAMETER Help
    Display this usage guide and exit.

.EXAMPLE
    # Typical use — reopen all feature worktrees and auto-continue Claude
    nm-reopen-worktrees.ps1 C:\src\erp2024

.EXAMPLE
    # Preview what would be opened without launching anything
    nm-reopen-worktrees.ps1 C:\src\erp2024 -DryRun

.EXAMPLE
    # Also open the main worktree
    nm-reopen-worktrees.ps1 C:\src\erp2024 -IncludeMain

.EXAMPLE
    # Interactively pick which worktrees to open
    nm-reopen-worktrees.ps1 C:\src\erp2024 -Select

.EXAMPLE
    # Pick interactively, preview the selection without launching
    nm-reopen-worktrees.ps1 C:\src\erp2024 -Select -DryRun

.EXAMPLE
    # Show an interactive session picker in each tab
    nm-reopen-worktrees.ps1 C:\src\erp2024 -UseResume

.EXAMPLE
    # Interactively pick worktrees to remove (local branch + worktree)
    nm-reopen-worktrees.ps1 C:\src\erp2024 -Cleanup

.EXAMPLE
    # Cleanup and also delete the branch on origin (no per-worktree prompt)
    nm-reopen-worktrees.ps1 C:\src\erp2024 -Cleanup -CleanupRemote

.EXAMPLE
    # Preview a cleanup — no destructive actions
    nm-reopen-worktrees.ps1 C:\src\erp2024 -Cleanup -DryRun

.EXAMPLE
    # Fully automated cleanup — no confirmations, force through dirty worktrees
    nm-reopen-worktrees.ps1 C:\src\erp2024 -Cleanup -CleanupRemote -Force

.NOTES
    Requirements:
      - Windows Terminal (wt.exe)         on PATH
      - PowerShell 7+ (pwsh)              on PATH (falls back to powershell.exe)
      - Claude Code (claude)              on PATH
      - The given path must be inside a git working tree.

    Plan mode is held in a session's runtime state and is NOT persisted across
    crashes.  After resuming, Claude will have full conversation history
    (including any planning discussion) but will not be back in plan mode.
    In each tab, ask:

        "what was the plan you produced?"

    to reconstruct it from the transcript.

    Raw Claude Code transcripts live at:
        %USERPROFILE%\.claude\projects\
    One folder per project path, .jsonl files inside, sorted by mtime.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$RepoPath,            # validated at runtime — no default

    [Alias('h')]
    [switch]$Help,

    [switch]$IncludeMain,
    [switch]$Select,
    [switch]$UseResume,
    [switch]$Cleanup,
    [switch]$CleanupRemote,
    [switch]$Force,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── OUTPUT HELPERS ───────────────────────────────────────────────────────────

function Write-Banner([string]$msg) {
    $pad  = 60
    $line = [string]::new([char]0x2500, $pad)
    Write-Host "`n  $([char]0x256D)$line$([char]0x256E)" -ForegroundColor Cyan
    Write-Host "  $([char]0x2502)  $($msg.PadRight($pad - 2))$([char]0x2502)" -ForegroundColor Cyan
    Write-Host "  $([char]0x2570)$line$([char]0x256F)`n" -ForegroundColor Cyan
}
function Write-Step([string]$msg)  { Write-Host "  $([char]0x25B6) $msg" -ForegroundColor Yellow }
function Write-OK([string]$msg)    { Write-Host "  $([char]0x2713) $msg" -ForegroundColor Green }
function Write-Skip([string]$msg)  { Write-Host "  $([char]0x00B7) $msg" -ForegroundColor DarkGray }
function Write-Warn([string]$msg)  { Write-Host "  $([char]0x26A0) $msg" -ForegroundColor Magenta }
function Write-Info([string]$msg)  { Write-Host "  $([char]0x2139) $msg" -ForegroundColor Cyan }
function Write-Err([string]$msg)   { Write-Host "  $([char]0x2717) $msg" -ForegroundColor Red }

function Show-Author {
    $width  = 56
    $hLine  = [string]::new([char]0x2500, $width)
    $tl     = [char]0x256D; $tr = [char]0x256E
    $bl     = [char]0x2570; $br = [char]0x256F
    $v      = [char]0x2502
    $esc    = [char]27
    $bold   = "$esc[1m"
    $reset  = "$esc[0m"

    # Prints a centered row: border in Cyan, text in $color
    function Row([string]$display, [string]$measure = $display, [string]$color = 'White') {
        $pad   = [Math]::Max(0, $width - $measure.Length)
        $left  = [Math]::Floor($pad / 2)
        $right = $pad - $left
        Write-Host "  $v" -NoNewline -ForegroundColor Cyan
        Write-Host "$(' ' * $left)$display$(' ' * $right)" -NoNewline -ForegroundColor $color
        Write-Host $v -ForegroundColor Cyan
    }

    $titlePlain   = 'nm-reopen-worktrees.ps1'
    $titleDisplay = "$bold$titlePlain$reset"

    Write-Host ''
    Write-Host "  $tl$hLine$tr"  -ForegroundColor Cyan
    Row ''
    Row $titleDisplay $titlePlain 'Cyan'
    Row 'Reopen worktrees & resume Claude Code' -color 'White'
    Row ''
    Row 'by Netmedia' -color 'DarkGray'
    Row 'https://netmedia.agency  |  netmedia@netmedia.hr' -color 'DarkGray'
    Row ''
    Write-Host "  $bl$hLine$br"  -ForegroundColor Cyan
    Write-Host ''
}

# ─── INTERACTIVE SELECTION ────────────────────────────────────────────────────

# Prompts the user to pick a subset of worktrees from a numbered list.
# Returns the selected worktrees (string[]). Re-prompts on invalid input.
# $Default controls what Enter/empty input means: 'all' or 'none'.
function Select-Worktrees {
    param(
        [string[]]$Worktrees,
        [string]  $MainWorktree,
        [ValidateSet('all','none')]
        [string]  $Default = 'all'
    )

    Write-Host ''
    Write-Info 'Selection format:  1,3,5  |  ranges 1-3  |  combined 1,3-5  |  a/all  |  n/none'

    while ($true) {
        Write-Host ''
        Write-Host "  Selection [$Default]: " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        $trimmed  = if ($null -ne $response) { $response.Trim() } else { '' }

        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            if ($Default -eq 'all') { return $Worktrees } else { return @() }
        }
        if ($trimmed -ieq 'a' -or $trimmed -ieq 'all')  { return $Worktrees }
        if ($trimmed -ieq 'n' -or $trimmed -ieq 'none') { return @() }

        # SortedSet keeps indices unique and ordered
        $indices = [System.Collections.Generic.SortedSet[int]]::new()
        $valid   = $true

        foreach ($part in ($trimmed -split ',')) {
            $p = $part.Trim()
            if (-not $p) { continue }

            if ($p -match '^(\d+)\s*-\s*(\d+)$') {
                $from = [int]$Matches[1]
                $to   = [int]$Matches[2]
                if ($from -lt 1 -or $to -gt $Worktrees.Count -or $from -gt $to) {
                    Write-Err "Invalid range: '$p'  (valid: 1-$($Worktrees.Count))"
                    $valid = $false
                    break
                }
                for ($i = $from; $i -le $to; $i++) { [void]$indices.Add($i - 1) }
            }
            elseif ($p -match '^\d+$') {
                $n = [int]$p
                if ($n -lt 1 -or $n -gt $Worktrees.Count) {
                    Write-Err "Out of range: '$p'  (valid: 1-$($Worktrees.Count))"
                    $valid = $false
                    break
                }
                [void]$indices.Add($n - 1)
            }
            else {
                Write-Err "Invalid token: '$p'"
                $valid = $false
                break
            }
        }

        if ($valid) {
            return @($indices | ForEach-Object { $Worktrees[$_] })
        }
    }
}

# ─── CLEANUP HELPERS ──────────────────────────────────────────────────────────

# Returns hashtable: worktree_path -> branch_name (or $null when detached HEAD).
# Parses  git worktree list --porcelain  which pairs a "worktree <path>" line
# with a following "branch refs/heads/<name>" line (or "detached" for no branch).
function Get-WorktreeBranchMap {
    param([string]$Root)

    Push-Location $Root
    try {
        $porcelain = & git worktree list --porcelain
    } finally {
        Pop-Location
    }

    $map = @{}
    $current = $null
    foreach ($line in $porcelain) {
        if ($line -like 'worktree *') {
            $current = $line.Substring(9)
            $map[$current] = $null      # default: detached
        }
        elseif ($current -and $line -like 'branch refs/heads/*') {
            $map[$current] = $line.Substring('branch refs/heads/'.Length)
        }
    }
    return $map
}

# Returns $true if the branch exists on the given remote.
function Test-BranchOnRemote {
    param(
        [string]$Root,
        [string]$Branch,
        [string]$Remote = 'origin'
    )
    if ([string]::IsNullOrWhiteSpace($Branch)) { return $false }
    Push-Location $Root
    try {
        $out = & git ls-remote --heads $Remote $Branch 2>$null
        return -not [string]::IsNullOrWhiteSpace($out)
    } finally {
        Pop-Location
    }
}

# Cleans up the selected worktrees using a plan-then-confirm-then-execute flow.
# Phase 1 — Plan:    inspect each selected worktree (dirty? branch? on remote?)
#                    and build a list of exact actions that would be taken.
# Phase 2 — Confirm: display the plan with a destructive-action summary, require
#                    the user to type YES (case-sensitive) unless -Force.
# Phase 3 — Execute: run  git worktree remove ,  git branch -D , and (optionally)
#                    git push --delete , then  git worktree prune  at the end.
# Skip rules:
#   - The main worktree is always skipped (removing it would break the repo).
#   - Dirty worktrees are skipped unless -Force is set.
function Invoke-CleanupWorktrees {
    param(
        [string[]]$Selected,
        [hashtable]$BranchMap,
        [string]$MainWorktree,
        [string]$Root,
        [bool]$AutoRemote,
        [bool]$ForceFlag,
        [bool]$IsDryRun
    )

    # ── Phase 1: Build the plan ──────────────────────────────────────────────
    $plan = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($wt in $Selected) {
        $entry = @{
            Path             = $wt
            Title            = Split-Path $wt -Leaf
            Branch           = if ($BranchMap.ContainsKey($wt)) { $BranchMap[$wt] } else { $null }
            IsMain           = ($wt -eq $MainWorktree)
            IsDirty          = $false
            OnRemote         = $false
            WillDeleteRemote = $false
            SkipReason       = $null
        }

        if ($entry.IsMain) {
            $entry.SkipReason = 'main worktree cannot be removed'
        }
        else {
            # Dirty check
            if (Test-Path $wt -PathType Container) {
                Push-Location $wt
                try {
                    $status = & git status --porcelain 2>$null
                    $entry.IsDirty = -not [string]::IsNullOrWhiteSpace($status)
                } finally { Pop-Location }
            }
            if ($entry.IsDirty -and -not $ForceFlag) {
                $entry.SkipReason = 'uncommitted changes (use -Force to remove)'
            }
            else {
                # Remote existence check (only for worktrees we're actually going to touch)
                if ($entry.Branch) {
                    $entry.OnRemote = Test-BranchOnRemote -Root $Root -Branch $entry.Branch
                    $entry.WillDeleteRemote = ($entry.OnRemote -and $AutoRemote)
                }
            }
        }

        $plan.Add($entry)
    }

    $toRemove        = @($plan | Where-Object { -not $_.SkipReason })
    $toSkip          = @($plan | Where-Object { $_.SkipReason })
    $localsToDelete  = @($toRemove | Where-Object { $_.Branch })
    $remotesToDelete = @($toRemove | Where-Object { $_.WillDeleteRemote })
    $remotesKept     = @($toRemove | Where-Object { $_.OnRemote -and -not $_.WillDeleteRemote })

    # ── Phase 2: Display the plan ────────────────────────────────────────────
    $maxTitle = 4  # min width so short names still look tidy
    foreach ($e in $plan) {
        $t = $e.Title.Length + $(if ($e.IsMain) { 7 } else { 0 })   # ' (MAIN)'
        if ($t -gt $maxTitle) { $maxTitle = $t }
    }
    $maxBranch = 6
    foreach ($e in $plan) {
        if ($e.Branch) {
            if ($e.Branch.Length -gt $maxBranch) { $maxBranch = $e.Branch.Length }
        }
    }

    Write-Host ''
    Write-Step "Cleanup plan  ($($toRemove.Count) to remove, $($toSkip.Count) skipped):"
    Write-Host ''

    foreach ($e in $plan) {
        $title = if ($e.IsMain) { "$($e.Title) (MAIN)" } else { $e.Title }
        $titleP  = $title.PadRight($maxTitle + 2)
        $branchP = ($(if ($e.Branch) { $e.Branch } else { '(detached)' })).PadRight($maxBranch + 2)

        if ($e.SkipReason) {
            Write-Host "    $([char]0x00B7)  " -NoNewline -ForegroundColor DarkGray
            Write-Host $titleP  -NoNewline -ForegroundColor DarkGray
            Write-Host $branchP -NoNewline -ForegroundColor DarkGray
            Write-Host "SKIP: $($e.SkipReason)" -ForegroundColor Yellow
        }
        else {
            Write-Host "    $([char]0x2717)  " -NoNewline -ForegroundColor Red     # ✗ = will be removed
            Write-Host $titleP  -NoNewline -ForegroundColor White
            Write-Host $branchP -NoNewline -ForegroundColor Cyan
            if ($e.WillDeleteRemote) {
                Write-Host '+ delete on origin' -ForegroundColor Magenta
            }
            elseif ($e.OnRemote) {
                Write-Host '(remote kept — use -CleanupRemote to also delete)' -ForegroundColor DarkGray
            }
            elseif ($e.Branch) {
                Write-Host '(local only, no remote)' -ForegroundColor DarkGray
            }
            else {
                Write-Host '(worktree only, no branch)' -ForegroundColor DarkGray
            }
        }
    }

    if ($toRemove.Count -eq 0) {
        Write-Host ''
        Write-Skip 'Nothing to remove.'
        return [ordered]@{ Cleaned = 0; RemoteDeleted = 0; Skipped = $toSkip.Count; Failed = 0 }
    }

    # Destructive summary panel
    Write-Host ''
    $line = [string]::new([char]0x2500, 60)
    Write-Host "  $([char]0x26A0)$([char]0x26A0)$([char]0x26A0)  DESTRUCTIVE ACTIONS  $line" -ForegroundColor Red
    Write-Host "     $([char]0x2022) $($toRemove.Count) worktree(s) will be removed"       -ForegroundColor White
    Write-Host "     $([char]0x2022) $($localsToDelete.Count) local branch(es) will be force-deleted (git branch -D)" -ForegroundColor White
    if ($remotesToDelete.Count -gt 0) {
        Write-Host "     $([char]0x2022) $($remotesToDelete.Count) remote branch(es) will be deleted on origin" -ForegroundColor White
    }
    if ($remotesKept.Count -gt 0) {
        Write-Host "     $([char]0x2022) $($remotesKept.Count) remote branch(es) will be KEPT on origin (no -CleanupRemote)" -ForegroundColor DarkGray
    }
    Write-Host "  $([char]0x26A0)  Local unmerged commits WILL BE LOST.  This cannot be undone." -ForegroundColor Red
    Write-Host "  $([char]0x2500)$line" -ForegroundColor Red

    # ── Phase 3: Confirmation gate ───────────────────────────────────────────
    if ($IsDryRun) {
        Write-Host ''
        Write-Info '[dry] Preview only — no actions performed.  Re-run without -DryRun to apply.'
        Write-Host ''
        return [ordered]@{
            Cleaned       = $toRemove.Count
            RemoteDeleted = $remotesToDelete.Count
            Skipped       = $toSkip.Count
            Failed        = 0
        }
    }

    if (-not $ForceFlag) {
        Write-Host ''
        Write-Host '  Type '   -NoNewline
        Write-Host 'YES'       -NoNewline -ForegroundColor Yellow
        Write-Host ' (uppercase, exact) to confirm — anything else cancels: ' -NoNewline
        $confirm = Read-Host
        if ($confirm -cne 'YES') {
            Write-Host ''
            Write-Skip 'Cancelled — no changes made.'
            return [ordered]@{ Cleaned = 0; RemoteDeleted = 0; Skipped = $toSkip.Count; Failed = 0 }
        }
        Write-OK 'Confirmed.'
    }
    else {
        Write-Host ''
        Write-Warn '-Force set — skipping confirmation.'
    }

    # ── Phase 4: Execute ─────────────────────────────────────────────────────
    $stats = [ordered]@{ Cleaned = 0; RemoteDeleted = 0; Skipped = $toSkip.Count; Failed = 0 }

    foreach ($e in $toRemove) {
        Write-Host ''
        Write-Step "Removing: $($e.Title)"

        # 1. Remove worktree
        $failed = $false
        Push-Location $Root
        try {
            $out = if ($e.IsDirty) {
                & git worktree remove --force $e.Path 2>&1
            } else {
                & git worktree remove $e.Path 2>&1
            }
            if ($LASTEXITCODE -ne 0) {
                Write-Err "  worktree remove failed: $out"
                $failed = $true
            } else {
                Write-OK "  worktree removed"
            }
        } finally { Pop-Location }

        if ($failed) { $stats.Failed++; continue }

        # 2. Delete local branch
        if ($e.Branch) {
            Push-Location $Root
            try {
                $out = & git branch -D $e.Branch 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-OK "  local branch deleted:  $($e.Branch)"
                } else {
                    Write-Warn "  local branch delete failed: $out"
                }
            } finally { Pop-Location }
        }

        # 3. Delete remote branch
        if ($e.WillDeleteRemote) {
            Push-Location $Root
            try {
                $out = & git push origin --delete $e.Branch 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-OK "  remote branch deleted: origin/$($e.Branch)"
                    $stats.RemoteDeleted++
                } else {
                    Write-Err "  remote branch delete failed: $out"
                }
            } finally { Pop-Location }
        }

        $stats.Cleaned++
    }

    # Prune stale worktree references
    Write-Host ''
    Push-Location $Root
    try {
        & git worktree prune 2>&1 | Out-Null
    } finally { Pop-Location }
    Write-OK 'Ran git worktree prune'

    return $stats
}


function Show-Usage {
    $hr = '  ' + ([string]::new([char]0x2500, 60))
    $b  = { param($t) Write-Host "  $t" -ForegroundColor White }
    $d  = { param($t) Write-Host "  $t" -ForegroundColor DarkGray }
    $g  = { param($t) Write-Host "  $t" -ForegroundColor Green }
    $y  = { param($t) Write-Host "  $t" -ForegroundColor Yellow }

    Write-Host ''
    & $b  'USAGE'
    & $g  '  nm-reopen-worktrees.ps1  <RepoPath>  [options]'
    Write-Host ''
    & $b  'REQUIRED'
    & $y  '  <RepoPath>'
    & $d  '    Path to any worktree of the repository (typically the main one).'
    & $d  '    Used to discover all worktrees via  git worktree list.'
    & $d  '    Accepts absolute or relative paths.'
    Write-Host ''
    & $b  'OPTIONS'
    & $y  '  -IncludeMain'
    & $d  '    Also open a tab for the main worktree.  Off by default — feature'
    & $d  '    work usually happens in feature worktrees branched off develop/main.'
    & $y  '  -Select'
    & $d  '    Show a numbered list of all worktrees and prompt for which to open.'
    & $d  '    Accepts:  1,3,5  |  ranges 1-3  |  combined 1,3-5  |  a/all  |  n/none'
    & $d  '    Implies -IncludeMain (main is always shown in the list).'
    & $y  '  -UseResume'
    & $d  '    Use  claude --resume  (interactive picker) instead of  claude --continue'
    & $d  '    (most recent session).  Use this when the session you want to resume'
    & $d  '    is not the most recent session in a given worktree.'
    & $y  '  -Cleanup'
    & $d  '    Enter cleanup mode.  Pick worktrees to REMOVE (worktree + local branch).'
    & $d  '    Builds a plan, shows a destructive-actions summary, then requires you'
    & $d  '    to type YES (uppercase, exact) before anything is touched.'
    & $d  '    Main worktree always skipped; dirty ones skipped unless -Force.'
    & $y  '  -CleanupRemote'
    & $d  '    Only meaningful with -Cleanup.  Also deletes branches on origin'
    & $d  '    when they exist there.  Otherwise remote branches are kept.'
    & $y  '  -Force'
    & $d  '    Skip the YES confirmation gate in -Cleanup mode, and force-remove'
    & $d  '    worktrees with uncommitted changes.  Use only when scripting'
    & $d  '    non-interactively — accidental use loses work.'
    & $y  '  -DryRun'
    & $d  '    List the worktrees that would be opened without launching anything.'
    & $d  '    Combine with -Select to interactively pick and verify before launching.'
    & $d  '    In -Cleanup mode, previews all removal actions without executing them.'
    & $y  '  -Help  (-h)'
    & $d  '    Show this usage guide and exit.'
    Write-Host ''
    & $b  'WHAT IT DOES'
    & $d  '  Reopen mode (default):'
    & $d  '    1. Validates that RepoPath is inside a git repository'
    & $d  '    2. Lists all worktrees via  git worktree list --porcelain'
    & $d  '    3. Displays a numbered list (with the main worktree marked)'
    & $d  '    4. Filters out the main worktree unless -IncludeMain or -Select'
    & $d  '    5. [-Select] Prompts for which worktrees to open (numbers/ranges/all/none)'
    & $d  '    6. Verifies wt.exe (Windows Terminal) is on PATH'
    & $d  '    7. Opens one Windows Terminal tab per chosen worktree, each starting'
    & $d  '       in the worktree directory and auto-running  claude --continue'
    & $d  ''
    & $d  '  Cleanup mode (-Cleanup):'
    & $d  '    1. Discovers and displays worktrees as above'
    & $d  '    2. Prompts for which worktrees to REMOVE (default: none — must be explicit)'
    & $d  '    3. Builds a plan: checks dirty state and remote branch existence'
    & $d  '    4. Shows the full plan + destructive-actions summary'
    & $d  '    5. Requires typing YES (uppercase, exact) to proceed — anything else cancels'
    & $d  '    6. Executes: worktree remove, branch -D, and (if -CleanupRemote) push --delete'
    & $d  '    7. Runs  git worktree prune  at the end'
    & $d  '    - Main worktree always skipped.  Dirty worktrees skipped unless -Force.'
    Write-Host ''
    & $b  'EXAMPLES'
    & $g  '  # Store the script centrally, call it with the repository path'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024'
    Write-Host ''
    & $g  '  # Preview which worktrees would be opened (no launch)'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024  -DryRun'
    Write-Host ''
    & $g  '  # Include the main worktree as well'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024  -IncludeMain'
    Write-Host ''
    & $g  '  # Use the interactive session picker in each tab'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024  -UseResume'
    Write-Host ''
    & $g  '  # Interactively pick which worktrees to open'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024  -Select'
    Write-Host ''
    & $g  '  # Pick interactively, preview without launching'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024  -Select  -DryRun'
    Write-Host ''
    & $g  '  # Cleanup mode — pick worktrees to remove (local only)'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024  -Cleanup'
    Write-Host ''
    & $g  '  # Cleanup + delete on origin when it exists there'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024  -Cleanup  -CleanupRemote'
    Write-Host ''
    & $g  '  # Preview a cleanup, no destructive actions'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024  -Cleanup  -DryRun'
    Write-Host ''
    & $g  '  # Fully automated cleanup — no prompts, force through dirty worktrees'
    & $g  '  C:\scripts\nm-reopen-worktrees.ps1  C:\src\erp2024  -Cleanup  -CleanupRemote  -Force'
    Write-Host ''
    & $b  'NOTES ON PLAN MODE'
    & $d  '  Plan mode is held in a session''s runtime state and is NOT persisted'
    & $d  '  across crashes.  After resuming, Claude will have full conversation'
    & $d  '  history (including any planning discussion) but will not be back'
    & $d  '  in plan mode.  In each tab, ask:'
    & $d  '    "what was the plan you produced?"'
    & $d  '  to reconstruct it from the transcript.'
    Write-Host ''
    & $b  'AFTER RUNNING'
    & $d  '  - Each tab opens in its worktree directory with Claude resuming.'
    & $d  '  - Tab titles match worktree folder names for quick scanning.'
    & $d  '  - Raw Claude transcripts live at:  %USERPROFILE%\.claude\projects\'
    Write-Host $hr -ForegroundColor Cyan
    Write-Host ''
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════════

# ── Author ────────────────────────────────────────────────────────────────────
Show-Author

# ── Show help and exit ────────────────────────────────────────────────────────
if ($Help -or [string]::IsNullOrWhiteSpace($RepoPath)) {
    if (-not $Help -and [string]::IsNullOrWhiteSpace($RepoPath)) {
        Write-Host "`n  ERROR: -RepoPath is required." -ForegroundColor Red
    }
    Show-Usage
    exit 0
}

# ── Resolve and validate path ─────────────────────────────────────────────────
if (-not (Test-Path $RepoPath -PathType Container)) {
    Write-Host "`n  ERROR: Path not found or is not a directory: $RepoPath`n" -ForegroundColor Red
    exit 1
}

$root = Resolve-Path $RepoPath | Select-Object -ExpandProperty Path

# Sanity: -CleanupRemote / -Force only make sense in cleanup mode
if (($CleanupRemote -or ($Force -and -not $Cleanup)) -and -not $Cleanup) {
    Write-Host "`n  ERROR: -CleanupRemote and -Force require -Cleanup.`n" -ForegroundColor Red
    exit 1
}

# -UseResume is meaningless in cleanup mode
if ($Cleanup -and $UseResume) {
    Write-Host "`n  ERROR: -UseResume cannot be combined with -Cleanup.`n" -ForegroundColor Red
    exit 1
}

if ($DryRun) {
    $dryLabel = if ($Cleanup) { 'no worktrees will be removed' } else { 'Windows Terminal will not be launched' }
    Write-Host "`n  ══ DRY RUN — $dryLabel ══" -ForegroundColor Cyan
}

Write-Banner "nm-reopen-worktrees.ps1"
Write-Host "  Repo    : $root" -ForegroundColor White
if ($Cleanup) {
    $modeDesc = if ($CleanupRemote) { 'CLEANUP (local + remote)' } else { 'CLEANUP (local, ask per-remote)' }
    Write-Host "  Mode    : $modeDesc" -ForegroundColor Magenta
} else {
    Write-Host "  Resume  : $(if ($UseResume) { 'claude --resume (picker)' } else { 'claude --continue (most recent)' })" -ForegroundColor White
}
Write-Host "  Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n" -ForegroundColor DarkGray

# ── 1. Validate repository ────────────────────────────────────────────────────
Write-Banner "[1/3] Validate Repository"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Err "git not found on PATH"
    exit 1
}
Write-OK "git detected"

Push-Location $root
try {
    $null = & git rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "'$root' is not inside a git working tree"
        exit 1
    }
    Write-OK "Path is inside a git working tree"
} finally {
    Pop-Location
}

# ── 2. Discover worktrees ─────────────────────────────────────────────────────
Write-Banner "[2/3] Discover Worktrees"

Push-Location $root
try {
    $porcelain = & git worktree list --porcelain
} finally {
    Pop-Location
}

$allWorktrees = @($porcelain |
    Where-Object { $_ -like 'worktree *' } |
    ForEach-Object { $_.Substring(9) })

if ($allWorktrees.Count -eq 0) {
    Write-Err "No worktrees reported by git"
    exit 1
}

# `git worktree list` always emits the main worktree first
$mainWorktree = $allWorktrees[0]

# Decide what's eligible. -Select and -Cleanup both show the main worktree in
# the list (main is still refused for removal — safety is enforced downstream).
if ($Select -or $Cleanup -or $IncludeMain) {
    $candidates = $allWorktrees
} else {
    $candidates = @($allWorktrees | Where-Object { $_ -ne $mainWorktree })
    if ($candidates.Count -eq 0) {
        Write-Warn "Only the main worktree exists — re-run with -IncludeMain or -Select to open it"
        exit 0
    }
}

$listLabel = if ($Cleanup) { 'listed' } else { 'selectable' }
Write-Info "Found $($allWorktrees.Count) worktree(s) — $($candidates.Count) ${listLabel}:"
Write-Host ''

# Numbered display — works for both -Select and non-Select modes.
# Compute column widths once for clean alignment.
$titleWidth = 0
foreach ($wt in $candidates) {
    $t = (Split-Path $wt -Leaf).Length
    if ($t -gt $titleWidth) { $titleWidth = $t }
}
if ($titleWidth -lt 20) { $titleWidth = 20 }
$indexWidth = ([string]$candidates.Count).Length

for ($i = 0; $i -lt $candidates.Count; $i++) {
    $wt     = $candidates[$i]
    $title  = Split-Path $wt -Leaf
    $isMain = ($wt -eq $mainWorktree)
    $marker = if ($isMain) { '(main)' } else { '      ' }
    $num    = ([string]($i + 1)).PadLeft($indexWidth)

    Write-Host "    [$num] " -NoNewline -ForegroundColor Yellow
    if ($isMain) {
        Write-Host "$marker " -NoNewline -ForegroundColor Magenta
    } else {
        Write-Host "$marker " -NoNewline -ForegroundColor DarkGray
    }
    Write-Host $title.PadRight($titleWidth) -NoNewline -ForegroundColor White
    Write-Host "  $wt" -ForegroundColor DarkGray
}

# Apply selection
if ($Select -or $Cleanup) {
    $default   = if ($Cleanup) { 'none' } else { 'all' }
    $worktrees = @(Select-Worktrees -Worktrees $candidates -MainWorktree $mainWorktree -Default $default)
    if ($worktrees.Count -eq 0) {
        Write-Host ''
        $noun = if ($Cleanup) { 'clean up' } else { 'open' }
        Write-Skip "No worktrees selected — nothing to $noun"
        exit 0
    }
    Write-Host ''
    $suffix = if ($Cleanup) { ' to clean up' } else { '' }
    Write-OK "Selected $($worktrees.Count) of $($candidates.Count) worktree(s)$suffix"
} else {
    $worktrees = $candidates
    if ($IncludeMain) {
        Write-OK "Including main worktree (-IncludeMain)"
    } else {
        Write-Skip "Skipping main worktree (use -IncludeMain or -Select to include it)"
    }
}

# ── 3. Cleanup or Open Terminal Tabs ──────────────────────────────────────────
if ($Cleanup) {
    Write-Banner "[3/3] Cleanup Worktrees"

    $branchMap = Get-WorktreeBranchMap -Root $root

    $stats = Invoke-CleanupWorktrees `
        -Selected     $worktrees `
        -BranchMap    $branchMap `
        -MainWorktree $mainWorktree `
        -Root         $root `
        -AutoRemote   ([bool]$CleanupRemote) `
        -ForceFlag    ([bool]$Force) `
        -IsDryRun     ([bool]$DryRun)

    # ── Summary (cleanup mode) ───────────────────────────────────────────────
    Write-Banner "Summary"
    Write-OK  "Repository       : $root"
    Write-OK  "Worktrees cleaned: $($stats.Cleaned)"
    if ($stats.RemoteDeleted -gt 0) { Write-OK   "Remote branches  : $($stats.RemoteDeleted) deleted" }
    if ($stats.Skipped -gt 0)       { Write-Skip "Skipped          : $($stats.Skipped)" }
    if ($stats.Failed  -gt 0)       { Write-Err  "Failed           : $($stats.Failed)" }

    Write-Host ''
    if ($DryRun) {
        Write-Host "  Re-run without -DryRun to apply these cleanups.`n" -ForegroundColor Cyan
    } elseif ($stats.Cleaned -gt 0) {
        Write-Host "  Cleanup complete.  Any unmerged local branches were force-deleted (-D)." -ForegroundColor Green
        if ($stats.RemoteDeleted -gt 0) {
            Write-Host "  Remote branches were deleted from origin. Ask teammates to run:"       -ForegroundColor Yellow
            Write-Host "    git fetch --prune`n"                                                 -ForegroundColor Yellow
        } else {
            Write-Host ''
        }
    } else {
        Write-Host "  No changes were made.`n" -ForegroundColor DarkGray
    }

    exit 0
}

# ── 3. Open Windows Terminal tabs (default mode) ──────────────────────────────
Write-Banner "[3/3] Open Terminal Tabs"

if (-not (Get-Command wt.exe -ErrorAction SilentlyContinue)) {
    Write-Err "wt.exe (Windows Terminal) was not found on PATH"
    exit 1
}
Write-OK "wt.exe detected"

if (Get-Command pwsh -ErrorAction SilentlyContinue) {
    $shell = 'pwsh'
    Write-OK "Shell: pwsh"
} else {
    $shell = 'powershell'
    Write-Warn "pwsh not found — falling back to powershell.exe"
}

if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
    Write-Warn "claude CLI not found on PATH — tabs will open but the resume command will fail."
    Write-Info "  Install: https://docs.claude.com/claude-code"
}

$claudeCmd = if ($UseResume) { 'claude --resume' } else { 'claude --continue' }

Write-Step "Will open $($worktrees.Count) tab(s):"
foreach ($wt in $worktrees) {
    $title = Split-Path $wt -Leaf
    Write-Info "  [$title]  $wt"
}

if ($DryRun) {
    Write-Host ''
    Write-Info "[dry] Would invoke wt.exe with the above tabs running:  $shell -NoExit -Command $claudeCmd"
    Write-Host ''
    exit 0
}

# Build the wt.exe argument list. Tabs are separated by a literal `;` argument.
$wtArgs = [System.Collections.Generic.List[string]]::new()
foreach ($wt in $worktrees) {
    if ($wtArgs.Count -gt 0) { $wtArgs.Add(';') }

    $title = Split-Path $wt -Leaf
    $wtArgs.AddRange([string[]]@(
        'new-tab',
        '--title', $title,
        '-d',      $wt,
        $shell, '-NoExit', '-Command', $claudeCmd
    ))
}

Write-Step "Launching Windows Terminal..."
& wt.exe @wtArgs
Write-OK "Launched $($worktrees.Count) tab(s)"

# ── Summary (default mode) ────────────────────────────────────────────────────
Write-Banner "Summary"

Write-OK  "Repository  : $root"
Write-OK  "Tabs opened : $($worktrees.Count)"
Write-Info "  Resume mode : $claudeCmd"
Write-Info "  Tab titles  : worktree folder names"

Write-Host ''
Write-Host "  Tip: plan mode is not persisted across crashes — ask Claude in each tab" -ForegroundColor DarkGray
Write-Host "       'what was the plan you produced?' to reconstruct it from history.`n"  -ForegroundColor DarkGray