#Requires -Version 5.1

#  ╔══════════════════════════════════════════════════════════════════════════╗
#  ║   netmedia-nm-protect-solution.ps1                                         ║
#  ║                                                                          ║
#  ║   Author  : Netmedia                                                     ║
#  ║   Web     : https://netmedia.agency                                      ║
#  ║   Email   : netmedia@netmedia.hr                                         ║
#  ╚══════════════════════════════════════════════════════════════════════════╝

<#
.SYNOPSIS
    Secures a .NET Core multi-project solution for safe AI-assisted development.

.AUTHOR
    Netmedia  |  https://netmedia.agency  |  netmedia@netmedia.hr

.DESCRIPTION
    Idempotent script that prepares any .NET Core solution for use with AI coding
    tools (Claude Code, GitHub Copilot, Cursor, etc.) by:

      1. Discovering all startup / web projects
      2. Initializing .NET User Secrets for each (if opted in)
      3. Scanning base JSON config files for committed secrets
      4. Extracting sensitive values → User Secrets AND/OR developer-override files
      5. Replacing extracted values with safe placeholders
      6. Detecting sensitive values in XML config files (manual guidance only)
      7. Updating .gitignore  — sensitive overrides, .env, license files
      8. Creating/updating .claudeignore  — same + binaries & generated content
      9. Detecting developer-override files already tracked by git and offering
         to untrack them with  git rm --cached
    10. [optional] Purging sensitive file paths from full git history using
         git-filter-repo  (requires  pip install git-filter-repo)

    Safe to run multiple times — idempotent.

.PARAMETER SolutionPath
    (Required) Root directory of the .NET solution.  The script locates the .sln
    file automatically inside this folder.  Can be an absolute or relative path.

.PARAMETER DryRun
    Show planned changes without modifying any files or running git commands.

.PARAMETER Force
    Re-process JSON config values that already contain a placeholder.

.PARAMETER SkipUserSecrets
    Do not initialise .NET User Secrets.  Use this when the project uses a custom
    config-override pattern (e.g. solutionsettings.DEVELOPMENT_{USER}.json).

.PARAMETER UntrackSensitiveFiles
    Automatically run  git rm --cached  on discovered sensitive override files
    that are currently tracked by git.  Without this flag the script only warns.

.PARAMETER ExtraIgnorePatterns
    Additional glob patterns appended to both .gitignore and .claudeignore.

.PARAMETER PurgeHistory
    Rewrite git history to permanently erase all sensitive file paths using
    git-filter-repo.  Requires  pip install git-filter-repo.
    Creates a backup branch automatically.  Prompts for confirmation unless
    -Force is also supplied.

.PARAMETER Help
    Display this usage guide and exit.

.EXAMPLE
    # Typical first run — preview, then apply
    nm-protect-solution.ps1 C:\projects\MyApp -DryRun
    nm-protect-solution.ps1 C:\projects\MyApp

.EXAMPLE
    # Project uses developer-override files instead of User Secrets
    nm-protect-solution.ps1 C:\projects\MyApp -SkipUserSecrets

.EXAMPLE
    # Sanitize configs AND untrack DEVELOPMENT_* files already committed to git
    nm-protect-solution.ps1 C:\projects\MyApp -SkipUserSecrets -UntrackSensitiveFiles

.EXAMPLE
    # Standard User Secrets mode with extra patterns to ignore
    nm-protect-solution.ps1 C:\projects\MyApp -ExtraIgnorePatterns "local.settings.json","*.pfx"

.EXAMPLE
    # Erase sensitive files from full git history (destructive — rewrites all SHAs)
    nm-protect-solution.ps1 C:\projects\MyApp -SkipUserSecrets -UntrackSensitiveFiles -PurgeHistory

.NOTES
    Store this script in a central location (e.g. C:\scripts\) and call it with
    the solution path.  It never needs to be copied into the solution folder.

    User Secrets storage:
      Windows  : %APPDATA%\Microsoft\UserSecrets\{id}\secrets.json
      Linux/Mac: ~/.microsoft/usersecrets/{id}/secrets.json

    After running:
      - Commit the updated .gitignore and .claudeignore.
      - If -UntrackSensitiveFiles was NOT used, run the suggested git rm commands.
      - Share actual secret values with teammates via a secure channel only.
      - Ensure startup projects call  builder.Configuration.AddUserSecrets<Program>()
        in Development mode (only needed if -SkipUserSecrets was NOT used).
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$SolutionPath,        # validated at runtime — no default

    [Alias('h')]
    [switch]$Help,

    [switch]$DryRun,
    [switch]$Force,
    [switch]$SkipUserSecrets,
    [switch]$UntrackSensitiveFiles,

    [string[]]$ExtraIgnorePatterns = @(),

    [switch]$PurgeHistory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── IDEMPOTENCY MARKERS ──────────────────────────────────────────────────────

$BEGIN_MARKER = '# ┌── protect-solution managed ──────────────────────────────────────┐'
$END_MARKER   = '# └── end protect-solution ──────────────────────────────────────────┘'

# ─── SAFE PLACEHOLDER ─────────────────────────────────────────────────────────

$PLACEHOLDER = '__REPLACE_WITH_SECRET__'

# ─── SENSITIVE KEY DETECTION ──────────────────────────────────────────────────

# Substrings (lowercased, separators stripped) that flag a JSON key as sensitive
$SENSITIVE_KEY_SUBSTRINGS = @(
    'password','passwd','pwd','pass',
    'secret','apikey','apitoken',
    'token','accesstoken','bearertoken','refreshtoken',
    'connectionstring','connectionstr',
    'clientsecret',
    'subscriptionkey','instrumentationkey',
    'accountkey','storagekey','storageaccount','blobstorage',
    'sendgrid','mailpassword','smtppassword','mailgun',
    'privatekey','signingkey','encryptionkey',
    'salt','hmackey','jwtkey','jwtsecret','authsecret'
)

# Value regexes that indicate a real secret regardless of key name
$SENSITIVE_VALUE_REGEXES = @(
    'Server=[^;]+;[^;]*(?:Password|Pwd)=\S',   # SQL connection string w/ password
    'AccountKey=[A-Za-z0-9+/]{20,}={0,2}',      # Azure Storage / Cosmos key
    'SharedAccessSignature',                      # Azure SAS token
    '^SG\.[A-Za-z0-9_\-]{22,}',                  # SendGrid API key
    '^sk-[A-Za-z0-9]{32,}',                       # OpenAI API key
    '^AKIA[A-Z0-9]{16}',                          # AWS Access Key ID
    'mongodb(\+srv)?://.+:.+@',                   # MongoDB with credentials
    'amqps?://.+:.+@',                            # AMQP / RabbitMQ / Service Bus
    'DefaultEndpointsProtocol=https?;AccountName=' # Azure Storage connection string
)

# ─── IGNORE FILE SECTIONS ─────────────────────────────────────────────────────

$GITIGNORE_SECTION = @(
    '# Sensitive per-developer / per-environment config overrides',
    'solutionsettings.DEVELOPMENT_*.json',
    'solutionsettings.DEVELOPMENT_*.JSON',
    'solutionsettings.LOCAL*.json',
    'solutionsettings.Staging*.json',
    'solutionsettings.Production*.json',
    'appsettings.Development.json',
    'appsettings.Staging.json',
    'appsettings.Production.json',
    '*.secrets.json',
    '',
    '# Environment variable files',
    '.env',
    '.env.*',
    '!.env.example',
    '',
    '# Third-party license / activation files',
    '*.lic',
    '*.license',
    '*.key',
    'Licenses/',
    'licenses/',
    '',
    '# Local publish output',
    'publish/',
    '*.pubxml.user'
)

$CLAUDEIGNORE_SECTION = @(
    '# ── Sensitive config overrides (real secrets, never for AI) ──────────',
    'solutionsettings.DEVELOPMENT_*.json',
    'solutionsettings.DEVELOPMENT_*.JSON',
    'solutionsettings.LOCAL*.json',
    'solutionsettings.Staging*.json',
    'solutionsettings.Production*.json',
    'appsettings.Development.json',
    'appsettings.Staging.json',
    'appsettings.Production.json',
    '*.secrets.json',
    '',
    '# ── Environment variable files ────────────────────────────────────────',
    '.env',
    '.env.*',
    '',
    '# ── Third-party license / activation files ────────────────────────────',
    '*.lic',
    '*.license',
    '*.key',
    'Licenses/',
    'licenses/',
    '**/Licenses/',
    '**/licenses/',
    '',
    '# ── Binary and generated documents (no code-review value) ────────────',
    '*.xlsx',
    '*.xls',
    '*.xlsm',
    '*.docx',
    '*.doc',
    '*.pdf',
    '*.zip',
    '*.tar',
    '*.tar.gz',
    '*.png',
    '*.jpg',
    '*.jpeg',
    '*.gif',
    '*.ico',
    '',
    '# ── User-uploaded / generated file storage ────────────────────────────',
    'FileSystem/',
    'uploads/',
    'wwwroot/uploads/',
    '',
    '# ── Build output ──────────────────────────────────────────────────────',
    'publish/',
    'bin/',
    'obj/',
    '*.user',
    '*.suo',
    '.vs/',
    '',
    '# ── Claude worktrees (internal tool artefacts) ────────────────────────',
    '.claude/worktrees/'
)

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

    $titlePlain   = 'nm-protect-solution.ps1'
    $titleDisplay = "$bold$titlePlain$reset"

    Write-Host ''
    Write-Host "  $tl$hLine$tr"  -ForegroundColor Cyan
    Row ''
    Row $titleDisplay $titlePlain 'Cyan'
    Row 'Secure a .NET solution for AI-assisted dev' -color 'White'
    Row ''
    Row 'by Netmedia' -color 'DarkGray'
    Row 'https://netmedia.agency  |  netmedia@netmedia.hr' -color 'DarkGray'
    Row ''
    Write-Host "  $bl$hLine$br"  -ForegroundColor Cyan
    Write-Host ''
}

# ─── DETECTION HELPERS ────────────────────────────────────────────────────────

function Test-SensitiveKey([string]$keyPath) {
    $norm = ($keyPath.ToLower() -replace '[-_\s\.]', '')
    foreach ($sub in $SENSITIVE_KEY_SUBSTRINGS) {
        if ($norm.Contains(($sub -replace '[-_]', ''))) { return $true }
    }
    return $false
}

function Test-SensitiveValue([string]$value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return $false }
    foreach ($rx in $SENSITIVE_VALUE_REGEXES) {
        if ($value -match $rx) { return $true }
    }
    return $false
}

function Test-IsPlaceholder([string]$value) {
    return [string]::IsNullOrWhiteSpace($value) -or
           $value -eq $PLACEHOLDER -or
           $value -match '^(PLACEHOLDER|YOUR_VALUE_HERE|<[A-Z0-9_]+>|__[A-Z0-9_]+__)$'
}

# ─── JSON HELPERS ─────────────────────────────────────────────────────────────

# Strip JS-style // line comments and /* */ block comments from JSON text
# Uses a simple state machine to avoid touching // inside string values.
function Remove-JsonComments([string]$json) {
    $sb        = [System.Text.StringBuilder]::new($json.Length)
    $i         = 0
    $inString  = $false
    $len       = $json.Length

    while ($i -lt $len) {
        $c = $json[$i]

        if ($inString) {
            [void]$sb.Append($c)
            # End of string — closing quote is unescaped when preceded by an even
            # number of backslashes (0, 2, 4 … means the backslashes escape each
            # other, not the quote; 1, 3, 5 … means the quote is escaped).
            if ($c -eq '"') {
                $bs = 0; $j = $i - 1
                while ($j -ge 0 -and $json[$j] -eq '\') { $bs++; $j-- }
                if (($bs % 2) -eq 0) { $inString = $false }
            }
        } elseif ($c -eq '"') {
            $inString = $true
            [void]$sb.Append($c)
        } elseif ($c -eq '/' -and ($i + 1) -lt $len -and $json[$i + 1] -eq '/') {
            # Single-line comment — skip to end of line
            while ($i -lt $len -and $json[$i] -ne "`n") { $i++ }
            continue
        } elseif ($c -eq '/' -and ($i + 1) -lt $len -and $json[$i + 1] -eq '*') {
            # Block comment — skip to */
            $i += 2
            while (($i + 1) -lt $len -and -not ($json[$i] -eq '*' -and $json[$i + 1] -eq '/')) { $i++ }
            $i += 2   # skip the closing */
            continue
        } else {
            [void]$sb.Append($c)
        }
        $i++
    }
    # Also remove trailing commas before } or ] (common in JSONC)
    return ($sb.ToString() -replace ',(\s*[}\]])', '$1')
}

# Recursively flatten a PSObject to an ordered hashtable { "A:B:C" = "value" }
function Expand-JsonPaths {
    param([psobject]$Node, [string]$Prefix = '')
    $map = [ordered]@{}
    if ($null -eq $Node) { return $map }
    foreach ($prop in $Node.PSObject.Properties) {
        $path = if ($Prefix) { "$Prefix`:$($prop.Name)" } else { $prop.Name }
        $val  = $prop.Value
        if ($val -is [System.Management.Automation.PSCustomObject]) {
            foreach ($kv in (Expand-JsonPaths -Node $val -Prefix $path).GetEnumerator()) {
                $map[$kv.Key] = $kv.Value
            }
        } elseif ($val -is [System.Array]) {
            # Arrays are not processed — secrets are rarely stored in arrays
        } else {
            $map[$path] = if ($null -ne $val) { [string]$val } else { '' }
        }
    }
    return $map
}

# Write a scalar value at a colon-separated path inside a PSObject
function Set-JsonPath {
    param([psobject]$Root, [string]$Path, [string]$Value)
    $parts   = $Path -split ':'
    $current = $Root
    for ($i = 0; $i -lt ($parts.Count - 1); $i++) {
        $next = $current.($parts[$i])
        if ($null -eq $next) { return }
        $current = $next
    }
    $current.($parts[-1]) = $Value
}

# ─── IGNORE FILE HELPER ───────────────────────────────────────────────────────

function Update-ManagedSection {
    param(
        [string]  $FilePath,
        [string[]]$SectionLines
    )
    $newSection = @($BEGIN_MARKER) + $SectionLines + @($END_MARKER)

    if (Test-Path $FilePath) {
        $lines = [System.IO.File]::ReadAllLines($FilePath)
        $bi = -1; $ei = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Trim() -eq $BEGIN_MARKER) { $bi = $i }
            if ($lines[$i].Trim() -eq $END_MARKER)   { $ei = $i; break }
        }
        if ($bi -ge 0 -and $ei -gt $bi) {
            $before  = if ($bi -gt 0)                       { $lines[0..($bi - 1)]              } else { @() }
            $after   = if ($ei -lt ($lines.Count - 1))      { $lines[($ei + 1)..($lines.Count - 1)] } else { @() }
            $updated = $before + $newSection + $after
            if (-not $DryRun) { [System.IO.File]::WriteAllLines($FilePath, $updated) }
            Write-OK "Updated managed section → $([IO.Path]::GetFileName($FilePath))"
        } else {
            $appended = $lines + @('') + $newSection
            if (-not $DryRun) { [System.IO.File]::WriteAllLines($FilePath, $appended) }
            Write-OK "Appended managed section → $([IO.Path]::GetFileName($FilePath))"
        }
    } else {
        if (-not $DryRun) { [System.IO.File]::WriteAllLines($FilePath, $newSection) }
        Write-OK "Created $([IO.Path]::GetFileName($FilePath))"
    }
}

# ─── PROJECT HELPERS ──────────────────────────────────────────────────────────

function Find-StartupProjects([string]$Root) {
    Get-ChildItem -Path $Root -Recurse -Filter '*.csproj' |
        Where-Object { $_.FullName -notmatch '[/\\](?:obj|bin|publish|\.git|\.claude)[/\\]' } |
        Where-Object {
            $c = Get-Content $_.FullName -Raw
            ($c -match 'Sdk\s*=\s*"Microsoft\.NET\.Sdk\.Web"') -or
            ($c -match '<OutputType>\s*Exe\s*</OutputType>')
        } |
        # Deduplicate — same file can be found via multiple search paths
        Sort-Object FullName -Unique
}

function Initialize-UserSecrets([System.IO.FileInfo]$Proj) {
    $c = Get-Content $Proj.FullName -Raw
    if ($c -match '<UserSecretsId>') {
        Write-Skip "UserSecretsId already present: $($Proj.Name)"
        return $true
    }
    Write-Step "dotnet user-secrets init → $($Proj.Name)"
    if (-not $DryRun) {
        $out = & dotnet user-secrets init --project $Proj.FullName 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Warn "Init failed: $out"; return $false }
    }
    Write-OK "User Secrets initialized: $($Proj.Name)"
    return $true
}

function Invoke-SetUserSecret([System.IO.FileInfo]$Proj, [string]$Key, [string]$Value) {
    if ($DryRun) {
        Write-Info "  [dry] user-secrets set `"$Key`" <redacted> --project $($Proj.Name)"
        return
    }
    $out = & dotnet user-secrets set $Key $Value --project $Proj.FullName 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warn "  Failed to set '$Key': $out" }
}

# ─── CONFIG PROCESSING ────────────────────────────────────────────────────────

function Invoke-ProcessJsonConfig {
    param(
        [string]              $Path,
        [System.IO.FileInfo[]]$Projects   # startup projects to store secrets in
    )
    $name = [IO.Path]::GetFileName($Path)
    $raw  = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)

    try   { $obj = $raw | ConvertFrom-Json }
    catch {
        # Retry after stripping JSONC comments (// and /* */) and trailing commas
        try   { $obj = (Remove-JsonComments $raw) | ConvertFrom-Json }
        catch { Write-Warn "$name — JSON/JSONC parse error, skipped: $_"; return }
    }

    $flat = Expand-JsonPaths -Node $obj
    $hits = [ordered]@{}

    foreach ($kv in $flat.GetEnumerator()) {
        $sensKey = Test-SensitiveKey  $kv.Key
        $sensVal = Test-SensitiveValue $kv.Value
        $isPH    = Test-IsPlaceholder  $kv.Value

        # Skip numeric-only values — config numbers are never secrets
        if ($kv.Value -match '^\d+(\.\d+)?$') { continue }
        # Skip purely boolean values
        if ($kv.Value -match '^(true|false)$') { continue }

        if (($sensKey -or $sensVal) -and (-not $isPH -or $Force)) {
            $hits[$kv.Key] = $kv.Value
        }
    }

    if ($hits.Count -eq 0) {
        Write-Skip "$name — no unmasked sensitive values found"
        return
    }

    Write-Step "$name — $($hits.Count) sensitive key(s):"

    foreach ($kv in $hits.GetEnumerator()) {
        Write-Info "    $($kv.Key)"

        # Store in User Secrets for each startup project
        if (-not $SkipUserSecrets) {
            foreach ($proj in $Projects) {
                Invoke-SetUserSecret -Proj $proj -Key $kv.Key -Value $kv.Value
            }
        }

        # Replace value with safe placeholder in the object
        Set-JsonPath -Root $obj -Path $kv.Key -Value $PLACEHOLDER
    }

    if (-not $DryRun) {
        $sanitized = $obj | ConvertTo-Json -Depth 20
        [IO.File]::WriteAllText($Path, $sanitized, [Text.Encoding]::UTF8)
    }

    $dest = if ($SkipUserSecrets) { "placeholder only (User Secrets skipped)" }
            else                  { "User Secrets + placeholder" }
    Write-OK "$name — $($hits.Count) value(s) extracted → $dest"
}

function Test-XmlConfigSensitive([string]$Path) {
    $name = [IO.Path]::GetFileName($Path)
    try   { [xml]$xml = Get-Content $Path -Raw }
    catch { Write-Warn "$name — XML parse error, skipped: $_"; return $false }

    $found = @()
    $xml.SelectNodes('//connectionStrings/add') | ForEach-Object {
        $cs = $_.GetAttribute('connectionString')
        if (Test-SensitiveValue $cs) { $found += "connectionStrings/$($_.GetAttribute('name'))" }
    }
    $xml.SelectNodes('//appSettings/add') | ForEach-Object {
        $k = $_.GetAttribute('key'); $v = $_.GetAttribute('value')
        if ((Test-SensitiveKey $k) -and -not (Test-IsPlaceholder $v)) {
            $found += "appSettings/$k"
        }
    }

    if ($found.Count -gt 0) {
        Write-Warn "$name — sensitive values detected (manual action required):"
        $found | ForEach-Object { Write-Warn "    $_" }
        Write-Info "  Fix: use  configSource=""$($name -replace '\.config$','.secrets.config')"""
        Write-Info "       then add  $($name -replace '\.config$','.secrets.config')  to .gitignore"
        return $true
    }
    Write-Skip "$name — no sensitive values detected"
    return $false
}

# ─── GIT HELPER ───────────────────────────────────────────────────────────────

function Find-TrackedSensitiveFiles([string]$Root) {
    $sensitiveGlobs = @(
        'solutionsettings.DEVELOPMENT_*',
        'solutionsettings.LOCAL*',
        'solutionsettings.Staging*',
        'solutionsettings.Production*',
        'appsettings.Development.json',
        'appsettings.Staging.json',
        'appsettings.Production.json',
        '*.secrets.json',
        '.env'
    )
    $tracked = @()
    $isGitRepo = Test-Path (Join-Path $Root '.git')
    if (-not $isGitRepo) { return $tracked }

    foreach ($glob in $sensitiveGlobs) {
        $out = & git -C $Root ls-files $glob 2>$null
        if ($out) { $tracked += ($out -split "`n" | Where-Object { $_ -ne '' }) }
    }
    return $tracked | Select-Object -Unique
}

# ─── PURGE HISTORY HELPERS ────────────────────────────────────────────────────

function Get-SensitivePurgePatterns {
    return @(
        'solutionsettings.DEVELOPMENT_*.json',
        'solutionsettings.DEVELOPMENT_*.JSON',
        'solutionsettings.LOCAL*.json',
        'solutionsettings.Staging*.json',
        'solutionsettings.Production*.json',
        'appsettings.Development.json',
        'appsettings.Staging.json',
        'appsettings.Production.json',
        '*.secrets.json',
        '.env',
        '.env.*',
        '*.lic',
        '*.license',
        '*.key'
    )
}

function Find-SensitiveFilesInHistory {
    param([string]$Root, [string[]]$Patterns)

    if (-not (Test-Path (Join-Path $Root '.git'))) { return @() }

    # All file paths ever added in history (across all branches)
    $raw = & git -C $Root log --all --name-only --diff-filter=A --pretty=format:"" 2>$null
    if (-not $raw) { return @() }

    $allFiles = ($raw -split "`n") | Where-Object { $_ -ne '' } | Sort-Object -Unique

    $matched = @()
    foreach ($file in $allFiles) {
        $basename = [IO.Path]::GetFileName($file)
        foreach ($pat in $Patterns) {
            if ($basename -like $pat -or $file -like $pat) {
                $matched += $file
                break
            }
        }
    }
    return $matched | Select-Object -Unique
}

function Invoke-PurgeHistory {
    param([string]$Root, [string[]]$FilePaths)

    # Verify git-filter-repo is available
    $hasFilterRepo = $false
    try {
        & git -C $Root filter-repo --version 2>&1 | Out-Null
        $hasFilterRepo = ($LASTEXITCODE -eq 0)
    } catch {}

    if (-not $hasFilterRepo) {
        Write-Err "git-filter-repo not found."
        Write-Info "  Install : pip install git-filter-repo"
        Write-Info "  Details : https://github.com/newren/git-filter-repo"
        return
    }

    if ($FilePaths.Count -eq 0) {
        Write-OK "No sensitive files found in git history — nothing to purge"
        return
    }

    Write-Warn "$($FilePaths.Count) sensitive path(s) found in git history:"
    $FilePaths | ForEach-Object { Write-Warn "    $_" }
    Write-Host ''
    Write-Warn "  !! THIS REWRITES ALL COMMIT SHAs ─ ALL COLLABORATORS MUST RE-CLONE !!"
    Write-Warn "  !! A backup branch is created automatically before proceeding.      !!"
    Write-Host ''

    if ($DryRun) {
        Write-Info "[dry] Would purge $($FilePaths.Count) path(s) from all branches and tags"
        Write-Info "[dry] Would create backup branch: backup/pre-purge-<timestamp>"
        return
    }

    if (-not $Force) {
        $answer = Read-Host "  Type YES to rewrite history and purge these files"
        if ($answer -ne 'YES') { Write-Skip "PurgeHistory cancelled"; return }
    }

    # Create backup branch before touching anything
    $backupBranch = "backup/pre-purge-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    & git -C $Root branch $backupBranch 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Backup branch created: $backupBranch"
    } else {
        Write-Warn "Could not create backup branch — proceeding anyway"
    }

    # Write exact paths to a temp file for filter-repo
    $pathsFile = Join-Path ([IO.Path]::GetTempPath()) "protect-purge-$([IO.Path]::GetRandomFileName()).txt"
    try {
        [IO.File]::WriteAllLines($pathsFile, $FilePaths)

        Write-Step "Running git filter-repo --invert-paths ..."
        $frOut = & git -C $Root filter-repo --invert-paths --paths-from-file $pathsFile --force 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-OK "History purged. $($FilePaths.Count) path(s) removed from all commits."
        } else {
            Write-Err "git filter-repo failed:"
            $frOut | ForEach-Object { Write-Err "  $_" }
        }
    } finally {
        Remove-Item $pathsFile -ErrorAction SilentlyContinue
    }

    # Print force-push instructions for each remote
    $remotes = (& git -C $Root remote 2>$null) -split "`n" | Where-Object { $_ -ne '' }
    if ($remotes) {
        Write-Host ''
        Write-Warn "Force-push required to update remote(s):"
        foreach ($remote in $remotes) {
            Write-Info "  git push $remote --force --all"
            Write-Info "  git push $remote --force --tags"
        }
        Write-Host ''
        Write-Warn "After pushing, all collaborators must re-clone:"
        Write-Info "  git clone <repo-url>"
        Write-Info "  (existing clones cannot be merged back — SHAs have changed)"
    }
}

# ─── USAGE ────────────────────────────────────────────────────────────────────

function Show-Usage {
    $c  = [char]0x1B   # ESC for ANSI — gracefully degrades on older consoles
    $w  = [char]0x1B   # unused fallback
    $nl = "`n"

    $hr  = '  ' + ([string]::new([char]0x2500, 60))
    $h   = { param($t) Write-Host "  $t" -ForegroundColor Cyan }
    $b   = { param($t) Write-Host "  $t" -ForegroundColor White }
    $d   = { param($t) Write-Host "  $t" -ForegroundColor DarkGray }
    $g   = { param($t) Write-Host "  $t" -ForegroundColor Green }
    $y   = { param($t) Write-Host "  $t" -ForegroundColor Yellow }

    Write-Host ''
    & $b  'USAGE'
    & $g  '  nm-protect-solution.ps1  <SolutionPath>  [options]'
    Write-Host ''
    & $b  'REQUIRED'
    & $y  '  <SolutionPath>'
    & $d  '    Root directory of the .NET solution (contains the .sln file).'
    & $d  '    The script finds the solution automatically inside this folder.'
    & $d  '    Accepts absolute or relative paths.'
    Write-Host ''
    & $b  'OPTIONS'
    & $y  '  -DryRun'
    & $d  '    Preview all planned changes without modifying any files.'
    & $y  '  -SkipUserSecrets'
    & $d  '    Skip .NET User Secrets setup. Use this when the project uses a'
    & $d  '    developer-override-file pattern (solutionsettings.DEVELOPMENT_*.json).'
    & $y  '  -UntrackSensitiveFiles'
    & $d  '    Run  git rm --cached  on sensitive override files already committed'
    & $d  '    to git. Without this flag the script only warns and prints commands.'
    & $y  '  -Force'
    & $d  '    Re-process JSON config values that already contain a placeholder.'
    & $y  '  -ExtraIgnorePatterns <string[]>'
    & $d  '    Extra glob patterns added to both .gitignore and .claudeignore.'
    & $y  '  -PurgeHistory'
    & $d  '    Rewrite git history to permanently remove sensitive file paths using'
    & $d  '    git-filter-repo (pip install git-filter-repo).  Creates a backup'
    & $d  '    branch first.  Prompts for confirmation unless -Force is also given.'
    & $y  '  -Help  (-h)'
    & $d  '    Show this usage guide and exit.'
    Write-Host ''
    & $b  'WHAT IT DOES'
    & $d  '  1. Discovers all startup / web projects inside SolutionPath'
    & $d  '  2. Initialises .NET User Secrets for each (unless -SkipUserSecrets)'
    & $d  '  3. Scans base JSON configs (appsettings*.json, solutionsettings*.json)'
    & $d  '     for committed secrets; replaces values with __REPLACE_WITH_SECRET__'
    & $d  '  4. Extracts those values into User Secrets (one set per startup project)'
    & $d  '  5. Detects sensitive values in XML configs (app.config / web.config)'
    & $d  '     and prints manual-action guidance'
    & $d  '  6. Finds license files (*.lic, *.license) and adds them to ignore lists'
    & $d  '  7. Updates .gitignore  — developer overrides, .env, license files'
    & $d  '  8. Creates/updates .claudeignore — same + binaries, FileSystem/, build output'
    & $d  '  9. Detects DEVELOPMENT_* / override files tracked by git and offers'
    & $d  '     to untrack them (-UntrackSensitiveFiles) or prints git rm commands'
    & $d  ' 10. [optional] Rewrites full git history to erase sensitive paths using'
    & $d  '     git-filter-repo  (-PurgeHistory)'
    & $d  '  Idempotent — safe to run multiple times on the same solution.'
    Write-Host ''
    & $b  'EXAMPLES'
    & $g  '  # Store the script centrally, call it with the solution path'
    & $g  '  C:\scripts\nm-protect-solution.ps1  C:\projects\MyApp'
    Write-Host ''
    & $g  '  # Preview first, then apply'
    & $g  '  C:\scripts\nm-protect-solution.ps1  C:\projects\MyApp  -DryRun'
    & $g  '  C:\scripts\nm-protect-solution.ps1  C:\projects\MyApp'
    Write-Host ''
    & $g  '  # Developer-override-file pattern (no User Secrets)'
    & $g  '  C:\scripts\nm-protect-solution.ps1  C:\projects\MyApp  -SkipUserSecrets'
    Write-Host ''
    & $g  '  # Sanitize + untrack already-committed developer files'
    & $g  '  C:\scripts\nm-protect-solution.ps1  C:\projects\MyApp  -SkipUserSecrets  -UntrackSensitiveFiles'
    Write-Host ''
    & $g  '  # Extra patterns to ignore (e.g. Azure Functions local settings)'
    & $g  '  C:\scripts\nm-protect-solution.ps1  C:\projects\MyApp  -ExtraIgnorePatterns "local.settings.json","*.pfx"'
    Write-Host ''
    & $g  '  # Permanently erase sensitive files from full git history (destructive)'
    & $g  '  C:\scripts\nm-protect-solution.ps1  C:\projects\MyApp  -SkipUserSecrets  -UntrackSensitiveFiles  -PurgeHistory'
    Write-Host ''
    & $b  'AFTER RUNNING'
    & $d  '  - Commit .gitignore and .claudeignore.'
    & $d  '  - If git rm commands were printed, run them and commit.'
    & $d  '  - Share real secret values with teammates via a secure channel only.'
    & $d  '  - User Secrets stored at:  %APPDATA%\Microsoft\UserSecrets\  (Windows)'
    & $d  '  - After -PurgeHistory: force-push all remotes and ask collaborators to re-clone.'
    Write-Host $hr -ForegroundColor Cyan
    Write-Host ''
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════════

# ── Author ────────────────────────────────────────────────────────────────────
Show-Author

# ── Show help and exit ────────────────────────────────────────────────────────
if ($Help -or [string]::IsNullOrWhiteSpace($SolutionPath)) {
    if (-not $Help -and [string]::IsNullOrWhiteSpace($SolutionPath)) {
        Write-Host "`n  ERROR: -SolutionPath is required." -ForegroundColor Red
    }
    Show-Usage
    exit 0
}

# ── Resolve and validate path ─────────────────────────────────────────────────
if (-not (Test-Path $SolutionPath -PathType Container)) {
    Write-Host "`n  ERROR: Path not found or is not a directory: $SolutionPath`n" -ForegroundColor Red
    exit 1
}

$root = Resolve-Path $SolutionPath | Select-Object -ExpandProperty Path

# ── Find .sln file ────────────────────────────────────────────────────────────
$slnFile = Get-ChildItem -Path $root -Filter '*.sln' -ErrorAction SilentlyContinue |
           Select-Object -First 1

if ($DryRun) {
    Write-Host "`n  ══ DRY RUN — no files will be modified ══" -ForegroundColor Cyan
}

Write-Banner "nm-protect-solution.ps1"
Write-Host "  Root    : $root" -ForegroundColor White
if ($slnFile) {
    Write-Host "  Solution: $($slnFile.Name)" -ForegroundColor White
} else {
    Write-Host "  Solution: (no .sln found — scanning for projects directly)" -ForegroundColor DarkYellow
}
Write-Host "  Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n" -ForegroundColor DarkGray

# ── 1. Startup projects ───────────────────────────────────────────────────────
Write-Banner "[1/8] Discover Startup Projects"
$startupProjects = @(Find-StartupProjects -Root $root)
if ($startupProjects.Count -eq 0) {
    Write-Warn "No Web or Exe projects found — User Secrets will be skipped"
    $SkipUserSecrets = $true
} else {
    $startupProjects | ForEach-Object { Write-Info $_.Name }
}

# ── 2. Initialize User Secrets ────────────────────────────────────────────────
Write-Banner "[2/8] Initialize User Secrets"
$readyProjects = @()
if ($SkipUserSecrets) {
    Write-Skip "Skipped (--SkipUserSecrets)"
} else {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        Write-Warn ".NET SDK not found in PATH — User Secrets skipped"
        $SkipUserSecrets = $true
    } else {
        foreach ($proj in $startupProjects) {
            if (Initialize-UserSecrets -Proj $proj) { $readyProjects += $proj }
        }
    }
}

# ── 3. Sanitize base JSON config files ───────────────────────────────────────
Write-Banner "[3/8] Sanitize JSON Config Files"

$jsonFiles = @()
foreach ($pat in @('appsettings*.json','solutionsettings*.json')) {
    Get-ChildItem -Path $root -Recurse -Filter $pat -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notmatch '[/\\](?:obj|bin|publish|\.git|\.claude)[/\\]' -and
            # Skip per-developer / per-environment overrides — they get gitignored
            $_.Name -notmatch 'DEVELOPMENT_|\.LOCAL\.|\.Staging\.|\.Production\.' -and
            $_.Name -inotmatch 'DEVELOPMENT_' -and
            $_.Name -notmatch '\.secrets\.json$'
        } |
        ForEach-Object { $jsonFiles += $_ }
}

if ($jsonFiles.Count -eq 0) {
    Write-Skip "No base JSON config files found"
} else {
    foreach ($f in $jsonFiles) {
        Invoke-ProcessJsonConfig -Path $f.FullName -Projects $readyProjects
    }
}

# ── 4. Check XML config files ─────────────────────────────────────────────────
Write-Banner "[4/8] Check XML Config Files"
$xmlSensitiveNames = @()
$xmlFiles = @(Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in @('app.config','web.config') -and
                   $_.FullName -notmatch '[/\\](?:obj|bin|publish|\.git|\.claude)[/\\]' })

if ($xmlFiles.Count -eq 0) {
    Write-Skip "No XML config files found"
} else {
    foreach ($f in $xmlFiles) {
        if (Test-XmlConfigSensitive -Path $f.FullName) { $xmlSensitiveNames += $f.Name }
    }
}

# ── 5. License files ──────────────────────────────────────────────────────────
Write-Banner "[5/8] License Files"
$licExtensions = @('.lic','.license')
$licFiles = @(Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in $licExtensions -and
                   $_.FullName -notmatch '[/\\](?:obj|bin|publish|\.git|\.claude)[/\\]' })
$licDirs  = @(Get-ChildItem -Path $root -Recurse -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -imatch '^licenses?$' -and
                   $_.FullName -notmatch '[/\\](?:obj|bin)[/\\]' })

if ($licFiles.Count -eq 0 -and $licDirs.Count -eq 0) {
    Write-Skip "No license files or Licenses/ directories found"
    Write-Info "Patterns (*.lic, *.license, Licenses/) are still added to ignore files"
} else {
    $licFiles | ForEach-Object { Write-Warn "License file : $($_.FullName.Replace($root,'.'))" }
    $licDirs  | ForEach-Object { Write-Warn "License dir  : $($_.FullName.Replace($root,'.'))" }
}

# ── 6. Tracked sensitive files in git ────────────────────────────────────────
Write-Banner "[6/8] Tracked Sensitive Files in Git"
$trackedSensitive = @(Find-TrackedSensitiveFiles -Root $root)
$rmCommands = @()

if ($trackedSensitive.Count -eq 0) {
    Write-OK "No sensitive override files are currently tracked by git"
} else {
    Write-Warn "$($trackedSensitive.Count) sensitive file(s) are tracked by git and should be untracked:"
    foreach ($f in $trackedSensitive) {
        Write-Warn "    $f"
        $rmCommands += "git rm --cached `"$f`""
    }

    if ($UntrackSensitiveFiles) {
        Write-Step "Running git rm --cached..."
        if (-not $DryRun) {
            foreach ($f in $trackedSensitive) {
                $out = & git -C $root rm --cached $f 2>&1
                if ($LASTEXITCODE -eq 0) { Write-OK "  Untracked: $f" }
                else                     { Write-Err "  Failed   : $f — $out" }
            }
        } else {
            $trackedSensitive | ForEach-Object { Write-Info "  [dry] git rm --cached `"$_`"" }
        }
    } else {
        Write-Info "  Run these commands (or re-run with -UntrackSensitiveFiles):"
        $rmCommands | ForEach-Object { Write-Info "    $_" }
    }
}

# ── 7. Purge sensitive files from git history ─────────────────────────────────
Write-Banner "[7/8] Purge History"
if ($PurgeHistory) {
    $purgePatterns = @(Get-SensitivePurgePatterns) + $ExtraIgnorePatterns
    $historyFiles  = @(Find-SensitiveFilesInHistory -Root $root -Patterns $purgePatterns)
    Invoke-PurgeHistory -Root $root -FilePaths $historyFiles
} else {
    Write-Skip "Skipped (use -PurgeHistory to erase sensitive paths from git history)"
}

# ── 8. Update ignore files ────────────────────────────────────────────────────
Write-Banner "[8/8] Update Ignore Files"

$extraSection = @()
if ($ExtraIgnorePatterns.Count -gt 0) {
    $extraSection += ''
    $extraSection += '# Extra patterns passed via -ExtraIgnorePatterns'
    $extraSection += $ExtraIgnorePatterns
}

Update-ManagedSection `
    -FilePath     (Join-Path $root '.gitignore') `
    -SectionLines ($GITIGNORE_SECTION + $extraSection)

Update-ManagedSection `
    -FilePath     (Join-Path $root '.claudeignore') `
    -SectionLines ($CLAUDEIGNORE_SECTION + $extraSection)

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Banner "Summary"

Write-OK ".gitignore  — managed section updated"
Write-OK ".claudeignore  — created / updated"

if ($readyProjects.Count -gt 0) {
    Write-OK "User Secrets configured for $($readyProjects.Count) project(s)"
    Write-Info "  Windows path : $env:APPDATA\Microsoft\UserSecrets\"
    Write-Info "  Ensure startup project(s) call:"
    Write-Info "    builder.Configuration.AddUserSecrets<Program>()"
    Write-Info "  (only needed in Development environment)"
}

if ($SkipUserSecrets -and $jsonFiles.Count -gt 0) {
    Write-Info "User Secrets were skipped — sensitive values were replaced with placeholders."
    Write-Info "Use your developer-override config files (e.g. solutionsettings.DEVELOPMENT_USER.json)"
    Write-Info "to supply real values locally.  These files are now gitignored."
}

if ($xmlSensitiveNames.Count -gt 0) {
    Write-Warn "XML configs requiring manual sanitisation:"
    $xmlSensitiveNames | ForEach-Object { Write-Warn "  $_" }
}

if ($trackedSensitive.Count -gt 0 -and -not $UntrackSensitiveFiles) {
    Write-Warn "Sensitive files still tracked by git — run with -UntrackSensitiveFiles or:"
    $rmCommands | ForEach-Object { Write-Warn "  $_" }
    Write-Info "  Then commit: git commit -m 'chore: untrack committed secrets'"
}

Write-Host ''
if ($DryRun) {
    Write-Host "  Re-run without -DryRun to apply all changes.`n" -ForegroundColor Cyan
} else {
    Write-Host "  Done. Commit .gitignore and .claudeignore, then share actual" -ForegroundColor Green
    Write-Host "  secret values with teammates via a secure channel only.`n"    -ForegroundColor Green
    if ($PurgeHistory) {
        Write-Host "  History was rewritten. Force-push all remotes and ask" -ForegroundColor Yellow
        Write-Host "  all collaborators to re-clone the repository.`n"       -ForegroundColor Yellow
    }
}
