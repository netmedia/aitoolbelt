#Requires -Version 5.1

#  ╔══════════════════════════════════════════════════════════════════════════╗
#  ║   nm-backup-restore-git.ps1                                              ║
#  ║                                                                          ║
#  ║   Author  : Netmedia                                                     ║
#  ║   Web     : https://netmedia.agency                                      ║
#  ║   Email   : netmedia@netmedia.hr                                         ║
#  ╚══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    Back up, verify, and restore git branches using bundle files and/or mirror
    clones — with an interactive picker and dry-run for every mode.

.AUTHOR
    Netmedia  |  https://netmedia.agency  |  netmedia@netmedia.hr

.DESCRIPTION
    A single tool for the "I'm about to clean up a repo and want a safety net"
    workflow.  Three modes:

      BACKUP  (default) — capture everything (local + all remote branches + tags)
                          into a portable .bundle file AND/OR a --mirror clone,
                          then verify what was written.
      VERIFY            — inspect an existing backup: validate it and list the
                          branches and tags it contains.
      RESTORE           — bring one/many branches back from a backup into a repo,
                          or clone the whole backup into a fresh folder.

    Two backup kinds are handled everywhere and auto-detected:
      - Bundle : a single .bundle file      (Test-Path -PathType Leaf)
      - Mirror : a bare  <name>.git  folder  (Test-Path -PathType Container)

    In RESTORE, two destination modes are auto-detected from -Target:
      - Fetch  : the path is inside an existing git working tree.  Selected
                 branches are fetched straight into it as local branches.
      - Clone  : the path does not exist (or is empty).  The whole backup is
                 cloned there, then the selected branch(es) are materialised.

    Restore is fully offline — the backup acts as the remote for  git fetch.

.PARAMETER Path
    (Required)  Meaning depends on mode:
      BACKUP  — path to the local repository to back up.
      VERIFY  — path to the backup (.bundle file OR mirror .git directory).
      RESTORE — path to the backup (.bundle file OR mirror .git directory).

.PARAMETER Target
    RESTORE only.  Destination repository folder.  Inside an existing git repo
    -> Fetch mode.  Missing or empty folder -> Clone mode.  Required for RESTORE
    unless -DryRun is used just to preview.

.PARAMETER Backup
    Select BACKUP mode.  This is the default when no mode switch is given.

.PARAMETER Verify
    Select VERIFY mode.

.PARAMETER Restore
    Select RESTORE mode.

.PARAMETER OutDir
    BACKUP only.  Folder to write backups into.  Defaults to the current folder.
    Created if it does not exist.

.PARAMETER RepoUrl
    BACKUP only.  Remote URL for the mirror clone.  If omitted, the URL of the
    'origin' remote is used.  If there is no origin and no -RepoUrl, the mirror
    is skipped (the bundle still captures local + fetched refs).

.PARAMETER BundleOnly
    BACKUP only.  Create just the bundle (skip the mirror).

.PARAMETER MirrorOnly
    BACKUP only.  Create just the mirror (skip the bundle).

.PARAMETER NoFetch
    BACKUP only.  Skip  git fetch --all --tags --prune  and the creation of local
    tracking branches for remote-only branches.  By default the script fetches
    first so the bundle's  --all  includes every remote branch too.

.PARAMETER Branch
    RESTORE only.  Restore a single named branch without prompting.  Errors (and
    lists what is available) if the branch is not in the backup.  Mutually
    exclusive with -Select.

.PARAMETER Select
    RESTORE only.  Show a numbered list of the branches in the backup and prompt
    for which to restore.  Accepts single numbers, ranges, and combinations:
        1,3,5      — pick #1, #3, #5
        1-3        — pick range #1 through #3
        1,3-5,8    — pick #1, #3 through #5, and #8
        a / all    — select all (Enter also = all)
        n / none   — cancel without restoring anything
    Without -Select and without -Branch, ALL branches are restored.

.PARAMETER Checkout
    RESTORE only.  After restoring, check the branch out.  Applied only when
    exactly one branch was restored.

.PARAMETER Force
    RESTORE only.  Overwrite a local branch that already exists with the same
    name (forced refspec).  Without it, existing branches are skipped.

.PARAMETER DryRun
    Preview everything without writing backups or modifying any repo.  Prints the
    plan and the exact git commands that would run.  In VERIFY it is a no-op
    (verify never writes anyway).

.PARAMETER Help
    Display this usage guide and exit.

.EXAMPLE
    # BACKUP — capture local + remote branches + tags as bundle AND mirror
    nm-backup-restore-git.ps1 C:\src\erp2024 -OutDir D:\backups

.EXAMPLE
    # BACKUP — bundle only, preview the commands first
    nm-backup-restore-git.ps1 C:\src\erp2024 -OutDir D:\backups -BundleOnly -DryRun

.EXAMPLE
    # VERIFY — what's inside a backup, and is it valid?
    nm-backup-restore-git.ps1 D:\backups\erp2024-20260720-101500.bundle -Verify

.EXAMPLE
    # RESTORE — one branch by name into an existing repo, then switch to it
    nm-backup-restore-git.ps1 D:\backups\erp2024.bundle C:\src\erp2024 -Restore -Branch feature/pricing -Checkout

.EXAMPLE
    # RESTORE — interactively pick which branches to bring back
    nm-backup-restore-git.ps1 D:\backups\erp2024.git C:\src\erp2024 -Restore -Select

.EXAMPLE
    # RESTORE — clone the whole backup into a fresh folder and land on main
    nm-backup-restore-git.ps1 D:\backups\erp2024.git C:\src\erp2024-restored -Restore -Branch main -Checkout

.NOTES
    Requirements:
      - git on PATH.
      - For a mirror, network access to the remote at backup time.

    A backup only contains what existed when it was captured.  A branch deleted
    AND garbage-collected before the backup will not appear.  Bundles do NOT
    include stashes — commit or pop them first if you need them.

    Recommended safety flow before deleting anything:
        nm-backup-restore-git.ps1 <repo> -OutDir <safe> -DryRun   # preview
        nm-backup-restore-git.ps1 <repo> -OutDir <safe>           # capture
        nm-backup-restore-git.ps1 <backup> -Verify                # confirm
        (copy the backup off the machine, then clean up)
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path,                # validated at runtime — no default

    [Parameter(Position = 1)]
    [string]$Target,              # RESTORE destination — validated at runtime

    [Alias('h')]
    [switch]$Help,

    # ── modes ──
    [switch]$Backup,
    [switch]$Verify,
    [switch]$Restore,

    # ── backup options ──
    [string]$OutDir,
    [string]$RepoUrl,
    [switch]$BundleOnly,
    [switch]$MirrorOnly,
    [switch]$NoFetch,

    # ── restore options ──
    [string]$Branch,
    [switch]$Select,
    [switch]$Checkout,
    [switch]$Force,

    # ── shared ──
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

    $titlePlain   = 'nm-backup-restore-git.ps1'
    $titleDisplay = "$bold$titlePlain$reset"

    Write-Host ''
    Write-Host "  $tl$hLine$tr"  -ForegroundColor Cyan
    Row ''
    Row $titleDisplay $titlePlain 'Cyan'
    Row 'Back up, verify & restore git branches' -color 'White'
    Row ''
    Row 'by Netmedia' -color 'DarkGray'
    Row 'https://netmedia.agency  |  netmedia@netmedia.hr' -color 'DarkGray'
    Row ''
    Write-Host "  $bl$hLine$br"  -ForegroundColor Cyan
    Write-Host ''
}

# ─── INTERACTIVE SELECTION ────────────────────────────────────────────────────

# Prompts the user to pick a subset of branches from a numbered list.
# Returns the selected branches (string[]). Re-prompts on invalid input.
# $Default controls what Enter/empty input means: 'all' or 'none'.
function Select-Branches {
    param(
        [string[]]$Branches,
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
            if ($Default -eq 'all') { return $Branches } else { return @() }
        }
        if ($trimmed -ieq 'a' -or $trimmed -ieq 'all')  { return $Branches }
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
                if ($from -lt 1 -or $to -gt $Branches.Count -or $from -gt $to) {
                    Write-Err "Invalid range: '$p'  (valid: 1-$($Branches.Count))"
                    $valid = $false
                    break
                }
                for ($i = $from; $i -le $to; $i++) { [void]$indices.Add($i - 1) }
            }
            elseif ($p -match '^\d+$') {
                $n = [int]$p
                if ($n -lt 1 -or $n -gt $Branches.Count) {
                    Write-Err "Out of range: '$p'  (valid: 1-$($Branches.Count))"
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
            return @($indices | ForEach-Object { $Branches[$_] })
        }
    }
}

# ─── BACKUP INSPECTION ────────────────────────────────────────────────────────

# Returns ref short-names of a given kind ('heads' or 'tags') from a backup.
# Handles both a .bundle file and a mirror .git directory.
function Get-BackupRefs {
    param(
        [string]$Path,
        [bool]  $IsBundle,
        [ValidateSet('heads','tags')]
        [string]$Kind
    )

    $names = [System.Collections.Generic.List[string]]::new()

    if ($IsBundle) {
        # `git bundle list-heads` prints:  <sha> <refname>
        $heads = & git bundle list-heads $Path 2>$null
        foreach ($line in $heads) {
            if ($line -match "\srefs/$Kind/(.+)$") {
                [void]$names.Add($Matches[1])
            }
        }
    }
    else {
        $refs = & git --git-dir=$Path for-each-ref --format='%(refname)' "refs/$Kind" 2>$null
        foreach ($line in $refs) {
            if ($line -match "^refs/$Kind/(.+)$") {
                [void]$names.Add($Matches[1])
            }
        }
    }

    return @($names | Sort-Object -Unique)
}

# ─── BACKUP CREATION ──────────────────────────────────────────────────────────

# Creates a bundle and/or mirror backup of $RepoPath and verifies each.
# Phase 1 — Prepare : optional  git fetch --all  + local tracking branches.
# Phase 2 — Create  : git bundle create --all  and/or  git clone --mirror.
# Phase 3 — Verify  : validate each artifact and count refs.
function Invoke-CreateBackup {
    param(
        [string]$RepoPath,
        [string]$OutDir,
        [string]$RepoUrl,
        [bool]  $DoBundle,
        [bool]  $DoMirror,
        [bool]  $DoFetch,
        [bool]  $IsDryRun
    )

    $stats = [ordered]@{ Bundle = $null; Mirror = $null; BundleRefs = 0; MirrorBranches = 0; MirrorTags = 0; Failed = 0 }

    $name  = Split-Path $RepoPath -Leaf
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $bundlePath = Join-Path $OutDir "$name-$stamp.bundle"
    $mirrorPath = Join-Path $OutDir "$name-$stamp.git"

    # Resolve the mirror source URL up front (needed for plan + execution).
    $mirrorUrl = $RepoUrl
    if ($DoMirror -and [string]::IsNullOrWhiteSpace($mirrorUrl)) {
        Push-Location $RepoPath
        try {
            $mirrorUrl = (& git remote get-url origin 2>$null)
        } finally { Pop-Location }
        if ([string]::IsNullOrWhiteSpace($mirrorUrl)) {
            Write-Warn "No 'origin' remote and no -RepoUrl — mirror will be skipped."
            $DoMirror = $false
        }
    }

    # ── Plan ──────────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Step "Backup plan:"
    Write-Host "      Repo    : $RepoPath"   -ForegroundColor White
    Write-Host "      Out dir : $OutDir"     -ForegroundColor White
    Write-Host "      Fetch   : $(if ($DoFetch) { 'yes (all remote branches + tags)' } else { 'no (-NoFetch)' })" -ForegroundColor DarkGray
    if ($DoBundle) { Write-Host "      Bundle  : $bundlePath" -ForegroundColor DarkGray } else { Write-Skip "Bundle  : skipped" }
    if ($DoMirror) { Write-Host "      Mirror  : $mirrorPath  (from $mirrorUrl)" -ForegroundColor DarkGray } else { Write-Skip "Mirror  : skipped" }

    if (-not $DoBundle -and -not $DoMirror) {
        Write-Host ''
        Write-Err "Nothing to do — both bundle and mirror are disabled."
        $stats.Failed = 1
        return $stats
    }

    # Stash warning (bundles don't capture stashes)
    Push-Location $RepoPath
    try { $stashCount = @(& git stash list 2>$null).Count } finally { Pop-Location }
    if ($stashCount -gt 0) {
        Write-Warn "You have $stashCount stash(es). Bundles do NOT include stashes — commit or pop them first."
    }

    if ($IsDryRun) {
        Write-Host ''
        Write-Info '[dry] Commands that WOULD run:'
        if ($DoFetch) {
            Write-Host "        git -C `"$RepoPath`" fetch --all --tags --prune" -ForegroundColor DarkGray
            Write-Host "        git -C `"$RepoPath`" branch --track <b> origin/<b>   (for each remote-only branch)" -ForegroundColor DarkGray
        }
        if ($DoBundle) { Write-Host "        git -C `"$RepoPath`" bundle create `"$bundlePath`" --all" -ForegroundColor DarkGray }
        if ($DoMirror) { Write-Host "        git clone --mirror `"$mirrorUrl`" `"$mirrorPath`"" -ForegroundColor DarkGray }
        Write-Host ''
        Write-Info '[dry] Preview only — no backups written.  Re-run without -DryRun to apply.'
        Write-Host ''
        return $stats
    }

    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $OutDir = (Resolve-Path $OutDir).Path

    # ── Phase 1: Prepare (fetch + tracking branches) ────────────────────────────
    if ($DoFetch) {
        Write-Host ''
        Write-Step "Fetching all remote branches and tags"
        Push-Location $RepoPath
        try {
            & git fetch --all --tags --prune 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { Write-OK "fetch complete" } else { Write-Warn "fetch reported issues (continuing)" }

            Write-Step "Creating local tracking branches for remote-only branches"
            $created = 0
            git branch -r |
                Where-Object { $_ -notmatch '->' } |
                ForEach-Object {
                    $b = $_.Trim() -replace '^origin/',''
                    & git branch --track $b "origin/$b" 2>$null
                    if ($LASTEXITCODE -eq 0) { $script:__wtCreated = $true; $created++ }
                }
            Write-OK "tracking branches ensured ($created new)"
        } finally { Pop-Location }
    }

    # ── Phase 2: Create ─────────────────────────────────────────────────────────
    if ($DoBundle) {
        Write-Host ''
        Write-Step "Creating bundle: $bundlePath"
        Push-Location $RepoPath
        try {
            $out = & git bundle create $bundlePath --all 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-OK "bundle created"
                $stats.Bundle = $bundlePath
            } else {
                Write-Err "bundle failed: $out"
                $stats.Failed++
            }
        } finally { Pop-Location }
    }

    if ($DoMirror) {
        Write-Host ''
        Write-Step "Creating mirror: $mirrorPath"
        $out = & git clone --mirror $mirrorUrl $mirrorPath 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-OK "mirror created"
            $stats.Mirror = $mirrorPath
        } else {
            Write-Err "mirror failed: $out"
            $stats.Failed++
        }
    }

    # ── Phase 3: Verify ───────────────────────────────────────────────────────
    Write-Host ''
    Write-Step "Verifying backups"

    if ($stats.Bundle) {
        & git bundle verify $stats.Bundle 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-OK "bundle verified OK" } else { Write-Warn "bundle verify reported issues" }
        $stats.BundleRefs = @(& git bundle list-heads $stats.Bundle 2>$null).Count
        Write-OK "bundle contains $($stats.BundleRefs) ref(s)"
    }

    if ($stats.Mirror) {
        $stats.MirrorBranches = @(Get-BackupRefs -Path $stats.Mirror -IsBundle $false -Kind 'heads').Count
        $stats.MirrorTags     = @(Get-BackupRefs -Path $stats.Mirror -IsBundle $false -Kind 'tags').Count
        Write-OK "mirror branches: $($stats.MirrorBranches)"
        Write-OK "mirror tags:     $($stats.MirrorTags)"
    }

    return $stats
}

# ─── BACKUP VERIFICATION / INSPECTION ─────────────────────────────────────────

# Validates a backup and lists its branches and tags.
function Invoke-VerifyBackup {
    param(
        [string]$Path,
        [bool]  $IsBundle
    )

    $stats = [ordered]@{ Valid = $false; Branches = 0; Tags = 0 }

    Write-Host ''
    Write-Step "Verifying: $Path"

    if ($IsBundle) {
        & git bundle verify $Path 2>&1 | Out-Null
        $stats.Valid = ($LASTEXITCODE -eq 0)
    } else {
        $null = & git --git-dir=$Path rev-parse --is-bare-repository 2>$null
        $stats.Valid = ($LASTEXITCODE -eq 0)
    }
    if ($stats.Valid) { Write-OK "backup is valid" } else { Write-Err "backup failed validation" }

    $branches = @(Get-BackupRefs -Path $Path -IsBundle $IsBundle -Kind 'heads')
    $tags     = @(Get-BackupRefs -Path $Path -IsBundle $IsBundle -Kind 'tags')
    $stats.Branches = $branches.Count
    $stats.Tags     = $tags.Count

    Write-Host ''
    Write-Info "Branches ($($branches.Count)):"
    if ($branches.Count -eq 0) { Write-Skip '  (none)' }
    $idxW = ([string]$branches.Count).Length
    for ($i = 0; $i -lt $branches.Count; $i++) {
        $num = ([string]($i + 1)).PadLeft($idxW)
        Write-Host "    [$num] " -NoNewline -ForegroundColor Yellow
        Write-Host $branches[$i] -ForegroundColor White
    }

    Write-Host ''
    Write-Info "Tags ($($tags.Count)):"
    if ($tags.Count -eq 0) { Write-Skip '  (none)' }
    else { Write-Host "    $($tags -join ', ')" -ForegroundColor DarkGray }

    return $stats
}

# ─── BRANCH RESTORE ───────────────────────────────────────────────────────────

# Restores the selected branches into the target repo.
# Phase 1 — Plan:    for Fetch mode, mark branches that already exist locally
#                    (skipped unless -Force).  For Clone mode, everything is new.
# Phase 2 — Display: show the plan and the exact git commands.
# Phase 3 — Execute: git fetch (Fetch mode) or git clone + branch (Clone mode),
#                    then optional checkout of a single restored branch.
function Invoke-RestoreBranches {
    param(
        [string[]]$Selected,
        [string]  $BackupPath,
        [bool]    $IsBundle,
        [string]  $RepoPath,
        [ValidateSet('fetch','clone')]
        [string]  $DestMode,
        [bool]    $DoCheckout,
        [bool]    $ForceFlag,
        [bool]    $IsDryRun
    )

    # ── Phase 1: Build the plan ──────────────────────────────────────────────
    $existingLocal = @()
    if ($DestMode -eq 'fetch') {
        Push-Location $RepoPath
        try {
            $existingLocal = @(& git branch --format='%(refname:short)' 2>$null)
        } finally { Pop-Location }
    }

    $plan = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($b in $Selected) {
        $exists = ($DestMode -eq 'fetch') -and ($existingLocal -contains $b)
        $entry = @{
            Branch     = $b
            Exists     = $exists
            SkipReason = $null
        }
        if ($exists -and -not $ForceFlag) {
            $entry.SkipReason = 'already exists locally (use -Force to overwrite)'
        }
        $plan.Add($entry)
    }

    $toRestore = @($plan | Where-Object { -not $_.SkipReason })
    $toSkip    = @($plan | Where-Object { $_.SkipReason })

    # ── Phase 2: Display the plan ────────────────────────────────────────────
    $maxName = 6
    foreach ($e in $plan) { if ($e.Branch.Length -gt $maxName) { $maxName = $e.Branch.Length } }

    Write-Host ''
    Write-Step "Restore plan  ($($toRestore.Count) to restore, $($toSkip.Count) skipped)  [mode: $DestMode]:"
    Write-Host ''

    foreach ($e in $plan) {
        $nameP = $e.Branch.PadRight($maxName + 2)
        if ($e.SkipReason) {
            Write-Host "    $([char]0x00B7)  " -NoNewline -ForegroundColor DarkGray
            Write-Host $nameP -NoNewline -ForegroundColor DarkGray
            Write-Host "SKIP: $($e.SkipReason)" -ForegroundColor Yellow
        }
        else {
            Write-Host "    $([char]0x2713)  " -NoNewline -ForegroundColor Green
            Write-Host $nameP -NoNewline -ForegroundColor White
            if ($e.Exists) {
                Write-Host 'overwrite existing local branch (-Force)' -ForegroundColor Magenta
            } else {
                Write-Host 'create local branch' -ForegroundColor DarkGray
            }
        }
    }

    if ($toRestore.Count -eq 0) {
        Write-Host ''
        Write-Skip 'Nothing to restore.'
        return [ordered]@{ Restored = 0; Skipped = $toSkip.Count; Failed = 0; CheckedOut = $null }
    }

    # Checkout feasibility note
    $checkoutTarget = $null
    if ($DoCheckout) {
        if ($toRestore.Count -eq 1) {
            $checkoutTarget = $toRestore[0].Branch
        } else {
            Write-Host ''
            Write-Warn "-Checkout ignored: more than one branch selected. Check out manually afterwards."
        }
    }

    # ── Phase 3: Dry run stops here ──────────────────────────────────────────
    if ($IsDryRun) {
        Write-Host ''
        Write-Info '[dry] Commands that WOULD run:'
        if ($DestMode -eq 'clone') {
            Write-Host "        git clone `"$BackupPath`" `"$RepoPath`"" -ForegroundColor DarkGray
            foreach ($e in $toRestore) {
                Write-Host "        git -C `"$RepoPath`" branch --track $($e.Branch) origin/$($e.Branch)" -ForegroundColor DarkGray
            }
        } else {
            foreach ($e in $toRestore) {
                $spec = if ($e.Exists) { "+refs/heads/$($e.Branch):$($e.Branch)" } else { "refs/heads/$($e.Branch):$($e.Branch)" }
                Write-Host "        git -C `"$RepoPath`" fetch `"$BackupPath`" $spec" -ForegroundColor DarkGray
            }
        }
        if ($checkoutTarget) {
            Write-Host "        git -C `"$RepoPath`" checkout $checkoutTarget" -ForegroundColor DarkGray
        }
        Write-Host ''
        Write-Info '[dry] Preview only — no changes made.  Re-run without -DryRun to apply.'
        Write-Host ''
        return [ordered]@{ Restored = $toRestore.Count; Skipped = $toSkip.Count; Failed = 0; CheckedOut = $checkoutTarget }
    }

    # ── Phase 4: Execute ─────────────────────────────────────────────────────
    $stats = [ordered]@{ Restored = 0; Skipped = $toSkip.Count; Failed = 0; CheckedOut = $null }

    if ($DestMode -eq 'clone') {
        Write-Host ''
        Write-Step "Cloning backup into: $RepoPath"
        $out = & git clone $BackupPath $RepoPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Err "  clone failed: $out"
            $stats.Failed = $toRestore.Count
            return $stats
        }
        Write-OK "  clone complete"

        foreach ($e in $toRestore) {
            Push-Location $RepoPath
            try {
                # Skip if clone already created it as the checked-out default branch
                $have = @(& git branch --format='%(refname:short)' 2>$null)
                if ($have -contains $e.Branch) {
                    Write-OK "  branch present: $($e.Branch)"
                } else {
                    $out = & git branch --track $e.Branch "origin/$($e.Branch)" 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-OK "  branch created: $($e.Branch)"
                    } else {
                        Write-Warn "  branch create failed: $out"
                        $stats.Failed++
                        continue
                    }
                }
                $stats.Restored++
            } finally { Pop-Location }
        }
    }
    else {
        foreach ($e in $toRestore) {
            Write-Host ''
            Write-Step "Fetching: $($e.Branch)"
            $spec = if ($e.Exists) { "+refs/heads/$($e.Branch):$($e.Branch)" } else { "refs/heads/$($e.Branch):$($e.Branch)" }
            Push-Location $RepoPath
            try {
                $out = & git fetch $BackupPath $spec 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-OK "  restored local branch: $($e.Branch)"
                    $stats.Restored++
                } else {
                    Write-Err "  fetch failed: $out"
                    $stats.Failed++
                }
            } finally { Pop-Location }
        }
    }

    # Optional checkout of a single restored branch
    if ($checkoutTarget -and $stats.Restored -gt 0) {
        Write-Host ''
        Write-Step "Checking out: $checkoutTarget"
        Push-Location $RepoPath
        try {
            $out = & git checkout $checkoutTarget 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-OK "  now on branch: $checkoutTarget"
                $stats.CheckedOut = $checkoutTarget
            } else {
                Write-Warn "  checkout failed: $out"
            }
        } finally { Pop-Location }
    }

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
    & $g  '  nm-backup-restore-git.ps1  <Path>  [<Target>]  [mode]  [options]'
    Write-Host ''
    & $b  'MODES'
    & $y  '  -Backup   (default)'
    & $d  '    <Path> = local repo to back up.  Writes a bundle and/or mirror'
    & $d  '    into -OutDir, then verifies each artifact.'
    & $y  '  -Verify'
    & $d  '    <Path> = a backup (.bundle file OR mirror .git dir).  Validates it'
    & $d  '    and lists the branches and tags it contains.'
    & $y  '  -Restore'
    & $d  '    <Path> = a backup;  <Target> = destination repo folder.  Brings'
    & $d  '    branch(es) back (fetch into an existing repo, or clone a fresh one).'
    Write-Host ''
    & $b  'ARGUMENTS'
    & $y  '  <Path>    (required)'
    & $d  '    Backup mode : local repository to back up.'
    & $d  '    Verify/Restore mode : the backup (.bundle file or mirror .git dir).'
    & $y  '  <Target>  (restore only)'
    & $d  '    Destination repo folder.  Inside an existing git repo -> Fetch mode.'
    & $d  '    Missing or empty folder -> Clone mode.  Required unless -DryRun.'
    Write-Host ''
    & $b  'BACKUP OPTIONS'
    & $y  '  -OutDir <dir>'
    & $d  '    Folder to write backups into (default: current folder).'
    & $y  '  -RepoUrl <url>'
    & $d  '    Remote URL for the mirror.  Defaults to the origin remote URL.'
    & $d  '    If there is no origin and no -RepoUrl, the mirror is skipped.'
    & $y  '  -BundleOnly / -MirrorOnly'
    & $d  '    Create only one of the two artifacts.'
    & $y  '  -NoFetch'
    & $d  '    Skip  git fetch --all --tags --prune  and tracking-branch creation.'
    & $d  '    By default the script fetches first so the bundle captures every'
    & $d  '    remote branch as well as your local ones.'
    Write-Host ''
    & $b  'RESTORE OPTIONS'
    & $y  '  -Branch <name>'
    & $d  '    Restore a single named branch without prompting.'
    & $y  '  -Select'
    & $d  '    Numbered picker.  Accepts:  1,3,5 | ranges 1-3 | 1,3-5 | a/all | n/none'
    & $d  '    Without -Select and without -Branch, ALL branches are restored.'
    & $y  '  -Checkout'
    & $d  '    Check the branch out afterwards (only when exactly one is restored).'
    & $y  '  -Force'
    & $d  '    Overwrite a local branch that already exists with the same name.'
    Write-Host ''
    & $b  'SHARED OPTIONS'
    & $y  '  -DryRun'
    & $d  '    Preview the plan and exact git commands without writing or changing'
    & $d  '    anything.  In Verify mode this is a no-op (verify never writes).'
    & $y  '  -Help  (-h)'
    & $d  '    Show this usage guide and exit.'
    Write-Host ''
    & $b  'EXAMPLES'
    & $g  '  # Back up a repo (bundle + mirror) into a safe folder'
    & $g  '  nm-backup-restore-git.ps1  C:\src\erp2024  -OutDir D:\backups'
    Write-Host ''
    & $g  '  # Preview a bundle-only backup first'
    & $g  '  nm-backup-restore-git.ps1  C:\src\erp2024  -OutDir D:\backups  -BundleOnly  -DryRun'
    Write-Host ''
    & $g  '  # Verify a backup and list what is inside it'
    & $g  '  nm-backup-restore-git.ps1  D:\backups\erp2024-20260720-101500.bundle  -Verify'
    Write-Host ''
    & $g  '  # Restore one branch by name and switch to it'
    & $g  '  nm-backup-restore-git.ps1  D:\backups\erp2024.bundle  C:\src\erp2024  -Restore  -Branch feature/pricing  -Checkout'
    Write-Host ''
    & $g  '  # Interactively pick branches to restore'
    & $g  '  nm-backup-restore-git.ps1  D:\backups\erp2024.git  C:\src\erp2024  -Restore  -Select'
    Write-Host ''
    & $g  '  # Clone the whole backup into a fresh folder and land on main'
    & $g  '  nm-backup-restore-git.ps1  D:\backups\erp2024.git  C:\src\erp2024-restored  -Restore  -Branch main  -Checkout'
    Write-Host ''
    & $b  'SAFETY FLOW (before deleting anything)'
    & $d  '  1. nm-backup-restore-git.ps1 <repo> -OutDir <safe> -DryRun   # preview'
    & $d  '  2. nm-backup-restore-git.ps1 <repo> -OutDir <safe>           # capture'
    & $d  '  3. nm-backup-restore-git.ps1 <backup> -Verify                # confirm'
    & $d  '  4. copy the backup off the machine, then clean up'
    Write-Host $hr -ForegroundColor Cyan
    Write-Host ''
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════════

# ── Author ────────────────────────────────────────────────────────────────────
Show-Author

# ── Show help and exit ────────────────────────────────────────────────────────
if ($Help -or [string]::IsNullOrWhiteSpace($Path)) {
    if (-not $Help -and [string]::IsNullOrWhiteSpace($Path)) {
        Write-Host "`n  ERROR: <Path> is required." -ForegroundColor Red
    }
    Show-Usage
    exit 0
}

# ── Resolve mode ──────────────────────────────────────────────────────────────
$modeCount = @($Backup, $Verify, $Restore | Where-Object { $_ }).Count
if ($modeCount -gt 1) {
    Write-Host "`n  ERROR: Choose only one of -Backup / -Verify / -Restore.`n" -ForegroundColor Red
    exit 1
}
$mode = if ($Restore) { 'restore' } elseif ($Verify) { 'verify' } else { 'backup' }

# ── Guard mismatched options ──────────────────────────────────────────────────
if ($Select -and $Branch) {
    Write-Host "`n  ERROR: -Select and -Branch cannot be combined.`n" -ForegroundColor Red
    exit 1
}
if ($BundleOnly -and $MirrorOnly) {
    Write-Host "`n  ERROR: -BundleOnly and -MirrorOnly are mutually exclusive.`n" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "`n  ERROR: git not found on PATH.`n" -ForegroundColor Red
    exit 1
}

if ($DryRun -and $mode -ne 'verify') {
    $what = if ($mode -eq 'backup') { 'no backups will be written' } else { 'the target repository will not be modified' }
    Write-Host "`n  ══ DRY RUN — $what ══" -ForegroundColor Cyan
}

Write-Banner "nm-backup-restore-git.ps1  ($mode)"

# ══════════════════════════════════════════════════════════════════════════════
# BACKUP MODE
# ══════════════════════════════════════════════════════════════════════════════
if ($mode -eq 'backup') {

    Write-Banner "[1/3] Validate Repository"

    if (-not (Test-Path $Path -PathType Container)) {
        Write-Err "Path not found or not a directory: $Path"
        exit 1
    }
    $repoResolved = Resolve-Path $Path | Select-Object -ExpandProperty Path

    Push-Location $repoResolved
    try {
        $null = & git rev-parse --is-inside-work-tree 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Err "'$repoResolved' is not inside a git working tree"
            exit 1
        }
    } finally { Pop-Location }
    Write-OK "Path is inside a git working tree"

    $outResolved = if ([string]::IsNullOrWhiteSpace($OutDir)) { (Get-Location).Path } else { $OutDir }

    Write-Banner "[2/3] Create Backups"
    $stats = Invoke-CreateBackup `
        -RepoPath  $repoResolved `
        -OutDir    $outResolved `
        -RepoUrl   $RepoUrl `
        -DoBundle  (-not $MirrorOnly) `
        -DoMirror  (-not $BundleOnly) `
        -DoFetch   (-not $NoFetch) `
        -IsDryRun  ([bool]$DryRun)

    Write-Banner "[3/3] Summary"
    Write-OK  "Repository       : $repoResolved"
    if ($stats.Bundle) { Write-OK  "Bundle           : $($stats.Bundle)  ($($stats.BundleRefs) refs)" }
    if ($stats.Mirror) { Write-OK  "Mirror           : $($stats.Mirror)  ($($stats.MirrorBranches) branches, $($stats.MirrorTags) tags)" }
    if ($stats.Failed -gt 0) { Write-Err "Failed artifacts : $($stats.Failed)" }

    Write-Host ''
    if ($DryRun) {
        Write-Host "  Re-run without -DryRun to write these backups.`n" -ForegroundColor Cyan
    } elseif ($stats.Bundle -or $stats.Mirror) {
        Write-Host "  Backup complete.  Copy the file(s) OFF this machine before you delete anything." -ForegroundColor Green
        Write-Host "  Verify any time with:" -ForegroundColor Yellow
        $sample = if ($stats.Bundle) { $stats.Bundle } else { $stats.Mirror }
        Write-Host "    nm-backup-restore-git.ps1 `"$sample`" -Verify`n" -ForegroundColor Yellow
    } else {
        Write-Host "  No backups were written.`n" -ForegroundColor DarkGray
    }
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# VERIFY / RESTORE MODES  (both operate on a backup)
# ══════════════════════════════════════════════════════════════════════════════

# ── Classify the backup ───────────────────────────────────────────────────────
Write-Banner "[1/3] Validate Backup"

if (-not (Test-Path $Path)) {
    Write-Err "Backup not found: $Path"
    exit 1
}
$backupResolved = Resolve-Path $Path | Select-Object -ExpandProperty Path
$isBundle = Test-Path $backupResolved -PathType Leaf

if ($isBundle) {
    & git bundle verify $backupResolved 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Not a valid git bundle: $backupResolved"
        exit 1
    }
    Write-OK "Backup kind: bundle file"
} else {
    $null = & git --git-dir=$backupResolved rev-parse --is-bare-repository 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Not a git repository (mirror) directory: $backupResolved"
        exit 1
    }
    Write-OK "Backup kind: mirror repository"
}
Write-Host "  Backup  : $backupResolved" -ForegroundColor White
Write-Host "  Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n" -ForegroundColor DarkGray

# ══════════════════════════════════════════════════════════════════════════════
# VERIFY MODE
# ══════════════════════════════════════════════════════════════════════════════
if ($mode -eq 'verify') {
    Write-Banner "[2/3] Inspect Contents"
    $stats = Invoke-VerifyBackup -Path $backupResolved -IsBundle ([bool]$isBundle)

    Write-Banner "[3/3] Summary"
    Write-OK  "Backup   : $backupResolved"
    if ($stats.Valid) { Write-OK "Status   : valid" } else { Write-Err "Status   : INVALID" }
    Write-OK  "Branches : $($stats.Branches)"
    Write-OK  "Tags     : $($stats.Tags)"
    Write-Host ''
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# RESTORE MODE
# ══════════════════════════════════════════════════════════════════════════════

# Determine destination mode from -Target
$destMode = $null
$repoResolved = $null
if (-not [string]::IsNullOrWhiteSpace($Target)) {
    if (Test-Path $Target -PathType Container) {
        $repoResolved = Resolve-Path $Target | Select-Object -ExpandProperty Path
        Push-Location $repoResolved
        try {
            $null = & git rev-parse --is-inside-work-tree 2>$null
            $inRepo = ($LASTEXITCODE -eq 0)
        } finally { Pop-Location }

        if ($inRepo) {
            $destMode = 'fetch'
        } else {
            $hasItems = @(Get-ChildItem -Force -LiteralPath $repoResolved).Count -gt 0
            if ($hasItems) {
                Write-Err "Destination exists, is not a git repo, and is not empty: $repoResolved"
                exit 1
            }
            $destMode = 'clone'
        }
    } else {
        $repoResolved = $Target
        $destMode = 'clone'
    }
    Write-OK "Destination mode: $destMode"
    Write-Host "  Target  : $repoResolved`n" -ForegroundColor White
} else {
    if (-not $DryRun) {
        Write-Err "<Target> is required for -Restore unless -DryRun is used to preview."
        exit 1
    }
    Write-Skip "No destination given — preview only (dry run)"
}

# ── Discover branches ─────────────────────────────────────────────────────────
Write-Banner "[2/3] Discover Branches"

$allBranches = @(Get-BackupRefs -Path $backupResolved -IsBundle ([bool]$isBundle) -Kind 'heads')
if ($allBranches.Count -eq 0) {
    Write-Err "No branches found in the backup."
    exit 1
}

Write-Info "Backup contains $($allBranches.Count) branch(es):"
Write-Host ''

$nameWidth = 0
foreach ($b in $allBranches) { if ($b.Length -gt $nameWidth) { $nameWidth = $b.Length } }
if ($nameWidth -lt 20) { $nameWidth = 20 }
$indexWidth = ([string]$allBranches.Count).Length

for ($i = 0; $i -lt $allBranches.Count; $i++) {
    $num = ([string]($i + 1)).PadLeft($indexWidth)
    Write-Host "    [$num] " -NoNewline -ForegroundColor Yellow
    Write-Host $allBranches[$i].PadRight($nameWidth) -ForegroundColor White
}

# ── Resolve which branches to restore ─────────────────────────────────────────
if ($Branch) {
    if ($allBranches -notcontains $Branch) {
        Write-Host ''
        Write-Err "Branch '$Branch' is not in the backup.  See the list above."
        exit 1
    }
    $selected = @($Branch)
    Write-Host ''
    Write-OK "Selected branch: $Branch"
}
elseif ($Select) {
    $selected = @(Select-Branches -Branches $allBranches -Default 'all')
    if ($selected.Count -eq 0) {
        Write-Host ''
        Write-Skip "No branches selected — nothing to restore"
        exit 0
    }
    Write-Host ''
    Write-OK "Selected $($selected.Count) of $($allBranches.Count) branch(es)"
}
else {
    $selected = $allBranches
    Write-Host ''
    Write-OK "Restoring all $($selected.Count) branch(es) (no -Select / -Branch given)"
}

# Preview-only restore with no destination
if ([string]::IsNullOrWhiteSpace($Target)) {
    Write-Host ''
    Write-Info "[dry] Preview only — no <Target> given.  Provide a destination to restore."
    Write-Banner "[3/3] Summary"
    Write-OK "Backup            : $backupResolved"
    Write-OK "Branches in backup: $($allBranches.Count)"
    Write-OK "Would restore     : $($selected.Count)"
    Write-Host ''
    exit 0
}

# ── Restore ───────────────────────────────────────────────────────────────────
Write-Banner "[3/3] Restore Branches"

$stats = Invoke-RestoreBranches `
    -Selected    $selected `
    -BackupPath  $backupResolved `
    -IsBundle    ([bool]$isBundle) `
    -RepoPath    $repoResolved `
    -DestMode    $destMode `
    -DoCheckout  ([bool]$Checkout) `
    -ForceFlag   ([bool]$Force) `
    -IsDryRun    ([bool]$DryRun)

Write-Banner "Summary"
Write-OK  "Backup           : $backupResolved"
Write-OK  "Destination      : $repoResolved  ($destMode)"
Write-OK  "Branches restored: $($stats.Restored)"
if ($stats.Skipped -gt 0) { Write-Skip "Skipped          : $($stats.Skipped)" }
if ($stats.Failed  -gt 0) { Write-Err  "Failed           : $($stats.Failed)" }
if ($stats.CheckedOut)    { Write-OK   "Checked out      : $($stats.CheckedOut)" }

Write-Host ''
if ($DryRun) {
    Write-Host "  Re-run without -DryRun to apply this restore.`n" -ForegroundColor Cyan
} elseif ($stats.Restored -gt 0) {
    Write-Host "  Restore complete.  Push a recovered branch back to origin with:" -ForegroundColor Green
    Write-Host "    git -C `"$repoResolved`" push origin <branch>`n" -ForegroundColor Yellow
} else {
    Write-Host "  No branches were restored.`n" -ForegroundColor DarkGray
}
