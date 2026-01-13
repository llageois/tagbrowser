#requires -version 5.1

# Tag browser - PowerShell GUI (WinForms)

# PS 5.1 compatible





# Script-scope state (init before StrictMode to avoid VariableIsUndefined)

$script:SearchWorker = $null

# ------------------------------ New globals (incremental features) ------------------------------
# Search history (last N searches)
$script:SearchHistory = New-Object System.Collections.ArrayList
$script:SearchHistoryMax = 25

# Duplicates option: hash-based confirmation (expensive but accurate; only hashes within candidate groups)
$script:DupUseHash = $false
$script:FileHashCache = @{}   # path -> @{ Hash=...; Size=...; LastWriteUtc=... }

$script:PendingSearchArgs = $null

$script:ColumnsFittedOnce = $false

$script:MainRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace

$script:SuppressFoundTagsEvent = $false



# --- Script-state initialization (required for StrictMode Latest) ---

$script:IsInitializing = $true


# Duplicate mode state
$script:DupModeEnabled = $false
$script:DupHideNonDuplicates = $true
$script:DupGroupByPath = $true  # option: group potential duplicates
$script:DupGroupMap = @{}       # map: Path -> group id
$script:DupTotal = 0
$script:ApplyingDupMode = $false
$script:DupApplying = $false  # guard to avoid re-entrant duplicate scan/apply under StrictMode
$script:DupSavedItems = $null  # stores full result list when entering duplicates mode (for restore)
$script:IsSearching = $false

# Network scan cache (to speed up repeated searches on large SMB shares)
$script:DirScanCache = @{}                 # key -> @{ BuiltUtc = [DateTime]::UtcNow; Files = [System.IO.FileInfo[]] }
$script:DirScanCacheMaxAgeSec = 600        # cache TTL (seconds) for network shares
$script:DirScanCacheEnabled = $true



$script:LastOpStatusLeft = ""  # last operation summary kept in left status (for view refresh)
$script:CancelSearchRequested = $false
$script:LastSearchInterrupted = $false
$script:IsRestoring = $true
# $script:RestoringSettings = $true  (moved above StrictMode)
$script:PendingSearchRequest = $null

# Selection restore (used to keep selection stable across actions/searches)
$script:PendingSelectionPaths = $null

$script:PendingSelectionCurrentPath = $null
$script:SuppressFoundTagsEvent = $false

$script:SearchWorker = $null

$script:PendingSearchArgs = $null

$script:ColumnsFittedOnce = $false

# --------------------------------------------------------------------




# Settings persistence state
$script:RestoringSettings = $true  # will be set to $false after Restore-Settings
$script:SettingsDirty = $false
$script:SettingsAutoSaveEnabled = $false
$script:_SettingsRestoredOnce = $false

Set-StrictMode -Version Latest


# Duplicate highlighting state
if (-not (Get-Variable -Name DuplicatesShown -Scope Script -ErrorAction SilentlyContinue)) { $script:DuplicatesShown = $false }
if (-not (Get-Variable -Name DuplicateColorsApplied -Scope Script -ErrorAction SilentlyContinue)) { $script:DuplicateColorsApplied = $false }
$ErrorActionPreference = "Stop"





# ------------------------------ Debug logging ------------------------------

$script:DEBUG = $true

function Debug-Log {

    param([string]$Msg)

    if (-not $script:DEBUG) { return }

    $ts = (Get-Date).ToString("HH:mm:ss.fff")

    try { Write-Host ("[DEBUG {0}] {1}" -f $ts, $Msg) } catch {}

}



function Normalize-FSPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace([string]$Path)) { return [string]$Path }
    $p = [string]$Path
    $p = $p.Trim()
    # Strip provider-qualified prefix if present (can happen with Resolve-Path on UNC)
    $prefix = 'Microsoft.PowerShell.Core\FileSystem::'
    if ($p.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $p = $p.Substring($prefix.Length)
    }
    # If the path exists, prefer the provider path (plain filesystem path)
    try {
        if (Test-Path -LiteralPath $p) {
            $rp = Resolve-Path -LiteralPath $p -ErrorAction Stop
            if ($rp -is [System.Array]) { $rp = $rp[0] }
            if ($rp -and ($rp.PSObject.Properties.Name -contains 'ProviderPath') -and $rp.ProviderPath) {
                $p = [string]$rp.ProviderPath
            } elseif ($rp -and ($rp.PSObject.Properties.Name -contains 'Path') -and $rp.Path) {
                $p = [string]$rp.Path
                if ($p.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { $p = $p.Substring($prefix.Length) }
            }
        }
    } catch { }
    return $p
}

function Add-RecentDir([string]$dir) {
    try {
        $dir = Normalize-FSPath $dir
        if ([string]::IsNullOrWhiteSpace($dir)) { return }

        if ($null -eq $script:RecentDirs) { $script:RecentDirs = New-Object System.Collections.ArrayList }

        # De-dup then prepend
        $script:RecentDirs = @($script:RecentDirs | Where-Object { $_ -and $_ -ne $dir })
        $script:RecentDirs = @($dir) + @($script:RecentDirs | Select-Object -First 20)

        if ($txtDir -and $txtDir.Items) {
            $txtDir.BeginUpdate()
            try {
                $txtDir.Items.Clear() | Out-Null
                foreach ($d in $script:RecentDirs) {
                    $dd = [string]$d
                    if (-not [string]::IsNullOrWhiteSpace($dd)) { [void]$txtDir.Items.Add($dd) }
                }
            } finally {
                $txtDir.EndUpdate()
            }

            # IMPORTANT: after Items.Clear(), ComboBox can blank its Text (esp. DropDownList).
            # Re-apply the text and cursor selection explicitly to avoid "Directory" being cleared after a search.
            try {
                $txtDir.Text = $dir

                # Select matching item if present
                $idx = -1
                for ($i=0; $i -lt $txtDir.Items.Count; $i++) {
                    if (($txtDir.Items[$i] -as [string]) -eq $dir) { $idx = $i; break }
                }
                if ($idx -ge 0) { $txtDir.SelectedIndex = $idx }
            } catch { }

            try {
                $len = 0
                try { $len = [int]$txtDir.Text.Length } catch { $len = 0 }
                $txtDir.SelectionStart = $len
                $txtDir.SelectionLength = 0
            } catch { }
        }
    } catch { }
}



function Write-DebugLog([string]$Message) { Debug-Log $Message }


# -------------------------------------------------------------------------



Add-Type -AssemblyName System.Windows.Forms

Add-Type -AssemblyName System.Drawing

Add-Type -AssemblyName Microsoft.VisualBasic

# --- Keyboard cues (mnemonics) ---
if (-not ('NativeMethods' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class NativeMethods {
  [DllImport("user32.dll", CharSet=CharSet.Auto)]
  public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
}
"@
}


function Set-UseMnemonic {
    param($Control)
    try {
        if ($null -ne $Control -and $Control.PSObject.Properties.Match("UseMnemonic").Count -gt 0) {
            $Control.UseMnemonic = $true
        }
    } catch {}
}

function Enable-KeyboardCues {
    param([System.Windows.Forms.Control]$Control)
    try {
        if ($null -eq $Control -or $Control.IsDisposed) { return }
        $h = $Control.Handle
        if ($h -eq [IntPtr]::Zero) { return }
        # WM_CHANGEUISTATE = 0x127
        # UIS_CLEAR = 2 ; UISF_HIDEFOCUS = 1 ; UISF_HIDEACCEL = 2
        [void][NativeMethods]::SendMessage($h, 0x127, [IntPtr]0x00010002, [IntPtr]::Zero) # clear hide focus
        [void][NativeMethods]::SendMessage($h, 0x127, [IntPtr]0x00020002, [IntPtr]::Zero) # clear hide accel
    } catch {}
}



# ------------------------------ Helpers ------------------------------



function Force-Array($x) {

    if ($null -eq $x) { return @() }

    if ($x -is [System.Array]) { return $x }

    return @($x)

}



# ------------------------------ Safe enumeration (avoid freezes on some folders) ------------------------------




function Get-DirCacheKey([string]$Dir) {
    try {
        if ([string]::IsNullOrWhiteSpace($Dir)) { return "" }
        $d = $Dir.Trim()
        $d = $d.TrimEnd('\','/')
        return $d.ToLowerInvariant()
    } catch {
        return [string]$Dir
    }
}

function Test-IsNetworkPath([string]$Path) {
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
        if ($Path.StartsWith('\\')) { return $true } # UNC
        $root = [System.IO.Path]::GetPathRoot($Path)
        if ([string]::IsNullOrWhiteSpace($root)) { return $false }
        $di = New-Object System.IO.DriveInfo($root)
        return ($di.DriveType -eq [System.IO.DriveType]::Network)
    } catch {
        return $false
    }
}

function Invalidate-DirScanCache([string]$Dir) {
    try {
        $key = Get-DirCacheKey $Dir
        if ($key -and $script:DirScanCache -and $script:DirScanCache.ContainsKey($key)) {
            [void]$script:DirScanCache.Remove($key)
            Debug-Log ("ScanCache: invalidated '{0}'" -f $Dir)
        }
    } catch { }
}

function Get-OrBuild-DirFileIndex([string]$Dir, [scriptblock]$CancelCheck, [switch]$ForceRefresh) {
    # Returns FileInfo[] for the full directory tree (no ext filtering), cached on NETWORK paths.
    # On local disks, returns $null so caller can use the normal traversal.
    try {
        if (-not $script:DirScanCacheEnabled) { return $null }
        if (-not (Test-IsNetworkPath $Dir)) { return $null }

        $key = Get-DirCacheKey $Dir
        if ([string]::IsNullOrWhiteSpace($key)) { return $null }

        if ($ForceRefresh) { Invalidate-DirScanCache $Dir }

        $entry = $null
        if ($script:DirScanCache.ContainsKey($key)) { $entry = $script:DirScanCache[$key] }

        if ($entry -and $entry.BuiltUtc) {
            try {
                $age = ([DateTime]::UtcNow - [DateTime]$entry.BuiltUtc).TotalSeconds
                if ($age -lt [double]$script:DirScanCacheMaxAgeSec -and $entry.Files) {
                    Debug-Log ("ScanCache: hit ({0} files)" -f (Get-Count $entry.Files))
                    return @($entry.Files)
                }
            } catch { }
        }

        Debug-Log ("ScanCache: build index for '{0}'" -f $Dir)
        $all = Get-FilesRecursiveSafe -Dir $Dir -AllowedExtsLower @() -CancelCheck $CancelCheck
        $script:DirScanCache[$key] = [pscustomobject]@{
            BuiltUtc = [DateTime]::UtcNow
            Files    = @($all)
        }
        return @($all)
    } catch {
        return $null
    }
}

function Get-FilesRecursiveSafe {

    param(

        [string]$Dir,

        [string[]]$AllowedExtsLower,
        [scriptblock]$CancelCheck,
        [switch]$NoSubdirs

    )
if ([string]::IsNullOrWhiteSpace($Dir) -or -not (Test-Path -LiteralPath $Dir)) { return @() }
    if ($NoSubdirs) {
        try {
            $di = New-Object System.IO.DirectoryInfo($Dir)
            $tmp = New-Object System.Collections.Generic.List[System.IO.FileInfo]
            try {
                foreach ($fi in $di.EnumerateFiles("*", [System.IO.SearchOption]::TopDirectoryOnly)) {
                    if ($CancelCheck -and (& $CancelCheck)) { break }
                    # Do NOT pre-filter by extension here; let the caller filter consistently.
                    [void]$tmp.Add($fi)
                }
            } catch { }
            return $tmp.ToArray()
        } catch {
            return @()
        }
    }




    $extFilter = @()

    if ($AllowedExtsLower -and (Get-Count $AllowedExtsLower) -gt 0) { $extFilter = @($AllowedExtsLower | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) }

    # Performance (especially on network shares):
    # - If MANY extensions are selected (ex: video files), doing one EnumerateFiles(pattern) per extension
    #   results in multiple directory listings per folder, which is often slower over SMB.
    # - Strategy used below:
    #     * 0 ext  -> EnumerateFiles() (all)
    #     * 1 ext  -> EnumerateFiles("*.<ext>") (server-side filtering)
    #     * >1 ext -> EnumerateFiles() once + in-memory extension HashSet filter (one listing per folder)
    $extSet = $null
    if ((Get-Count $extFilter) -gt 1) {
        try {
            $extSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($e in $extFilter) { [void]$extSet.Add($e) }
        } catch { $extSet = $null }
    }



    # PS 5.1 (.NET Framework) safe traversal:

    # - skips reparse points (junctions/symlinks) to avoid loops

    # - ignores access errors

    # - filters by extension early (optional)

    # - optional cancellation via -CancelCheck

    $results = New-Object System.Collections.Generic.List[System.IO.FileInfo]

    $stack   = New-Object System.Collections.Generic.Stack[string]

    $stack.Push($Dir)



    $dirTick  = 0

    $fileTick = 0



    while ($stack.Count -gt 0) {

        if ($CancelCheck -and (& $CancelCheck)) { break }



        $current = $stack.Pop()

        if ([string]::IsNullOrWhiteSpace($current)) { continue }



        $di = $null

        try { $di = [System.IO.DirectoryInfo]::new($current) } catch { $di = $null }

        if ($null -eq $di) { continue }



        # Files

        try {

	    $extCount = Get-Count $extFilter

	    if ($extCount -eq 1) {
	        # Single extension -> server-side filtering is usually beneficial
	        $pattern = "*" + $extFilter[0]
	        foreach ($fi in $di.EnumerateFiles($pattern)) {
	            if ($CancelCheck -and (& $CancelCheck)) { break }
	            [void]$results.Add($fi)
	            $fileTick++
	            if (($fileTick % 400) -eq 0) { try { [System.Windows.Forms.Application]::DoEvents() } catch {} }
	        }
	    }
	    elseif ($extCount -gt 1 -and $null -ne $extSet) {
	        # Many extensions -> do ONE listing per folder, then filter in-memory (avoid N listings per folder over SMB)
	        foreach ($fi in $di.EnumerateFiles()) {
	            if ($CancelCheck -and (& $CancelCheck)) { break }
	            try {
	                if (-not $extSet.Contains($fi.Extension)) { continue }
	            } catch {
	                continue
	            }
	            [void]$results.Add($fi)
	            $fileTick++
	            if (($fileTick % 400) -eq 0) { try { [System.Windows.Forms.Application]::DoEvents() } catch {} }
	        }
	    }
	    else {
	        # No extension filter (or extSet failed) -> enumerate all files
	        foreach ($fi in $di.EnumerateFiles()) {
	            if ($CancelCheck -and (& $CancelCheck)) { break }
	            [void]$results.Add($fi)
	            $fileTick++
	            if (($fileTick % 400) -eq 0) { try { [System.Windows.Forms.Application]::DoEvents() } catch {} }
	        }
	    }

        } catch {

            # ignore

        }


        # Subdirectories (skip reparse points)

        try {

            foreach ($sub in $di.EnumerateDirectories()) {

                if ($CancelCheck -and (& $CancelCheck)) { break }

                try {

                    if (($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }

                } catch { continue }

                $stack.Push($sub.FullName)

                $dirTick++

                if (($dirTick % 100) -eq 0) { try { [System.Windows.Forms.Application]::DoEvents() } catch {} }

            }

        } catch {

            # ignore

        }

    }



    return $results.ToArray()

}



function Get-Count($x) {

    if ($null -eq $x) { return 0 }

    if ($x -is [string]) { return 1 }

    if ($x -is [System.Array]) { return $x.Count }

    if ($x -is [System.Collections.ICollection]) { return $x.Count }

    try {

        # IEnumerable (ex: DataGridViewSelectedRowCollection) => on compte par énumération

        $n = 0

        foreach ($item in $x) { $n++ }

        return $n

    } catch {

        return 1

    }

}

# Implementation stored in a script-scoped scriptblock to avoid scope-qualified function name resolution issues

$script:SafeTrimLowerImpl = {

    param([string]$s)

    if ($null -eq $s) { return "" }

    return $s.Trim().ToLowerInvariant()

}



function script:Safe-TrimLower {

    param([string]$s)

    return (& $script:SafeTrimLowerImpl $s)

}



# Expose also in global scope so that deferred scriptblocks/events can always resolve it

function global:Safe-TrimLower {

    param([string]$s)

    return (& $script:SafeTrimLowerImpl $s)

}



# --- Safe-ToLower (non-recursive, strictmode-safe) ---

# Use a scriptblock implementation stored in GLOBAL scope to avoid any scope-resolution recursion.

$global:SafeToLowerImpl = {

    param([string]$s)

    if ([string]::IsNullOrWhiteSpace($s)) { return "" }

    return $s.ToLowerInvariant()

}



function Safe-ToLower {

    param([string]$s)

    return (& $global:SafeToLowerImpl $s)

}



function global:Safe-ToLower {

    param([string]$s)

    return (& $global:SafeToLowerImpl $s)

}



function Get-BodyFromNameNoExt([string]$nameNoExt) {

    if ([string]::IsNullOrWhiteSpace($nameNoExt)) { return "" }

    $s = $nameNoExt.Trim()

    if (-not $s.EndsWith(")")) { return $s }

    $lastOpen = $s.LastIndexOf("(")

    if ($lastOpen -lt 0) { return $s }

    $body = $s.Substring(0, $lastOpen).TrimEnd()

    return $body

}



function Get-TagsFromNameNoExt([string]$nameNoExt) {

    if ([string]::IsNullOrWhiteSpace($nameNoExt)) { return @() }

    $s = $nameNoExt.Trim()

    if (-not $s.EndsWith(")")) { return @() }

    $lastOpen = $s.LastIndexOf("(")

    if ($lastOpen -lt 0) { return @() }



    # inner = contenu de la dernière paire de parenthèses

    $inner = $s.Substring($lastOpen + 1)

    if ($inner.EndsWith(")")) {

        $inner = $inner.Substring(0, $inner.Length - 1)

    }

    $inner = $inner.Trim()

    if ($inner -eq "") { return @() }



    # Tags séparés par " + "

    $parts = $inner -split '\s+\+\s+'

    $list = New-Object System.Collections.Generic.List[string]

    foreach ($p in $parts) {

        $t = Safe-TrimLower $p

        if ($t -ne "") { [void]$list.Add($t) }

    }

    return $list.ToArray()

}



function Normalize-Tags([string[]]$Tags) {

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($t in (Force-Array $Tags)) {

        $x = Safe-TrimLower $t

        if ($x -ne "") { [void]$set.Add($x) }

    }



    $arr = @($set) | Sort-Object



    # tags en tête : cl, ps

    $front = @()

    foreach ($p in @("cl","ps")) {

        if ($arr -contains $p) { $front += $p }

    }



    # suffixes en fin : *cim, *cob, *cif, *swa

    $backSuffix = @("cim","cob","cif","swa")

    $back = @()

    $mid  = @()



    foreach ($t in $arr) {

        if ($front -contains $t) { continue }

        $isBack = $false

        foreach ($suf in $backSuffix) {

            if ($t -like "*$suf") { $isBack = $true; break }

        }

        if ($isBack) { $back += $t } else { $mid += $t }

    }



    return [string[]]@($front + $mid + $back)

}



function Build-NewName([string]$Body, [string[]]$Tags, [string]$Ext) {

    $b = ""

    if ($null -ne $Body) { $b = $Body.Trim() }



    $t = Normalize-Tags $Tags

    if ((Get-Count $t) -gt 0) {

        # Sur disque : toujours "a + b + c"

        return ($b + " (" + ($t -join " + ") + ")" + $Ext)

    }

    return ($b + $Ext)

}



# ------------------------------ Filter parsing (et/ou/non + parentheses) ------------------------------



function Tokenize-Expr([string]$Expr) {

    $Expr = Safe-TrimLower $Expr

    if ($Expr -eq "") { return @() }



    $toks = New-Object System.Collections.Generic.List[object]

    $i = 0

    while ($i -lt $Expr.Length) {

        $ch = $Expr[$i]

        if ([char]::IsWhiteSpace($ch)) { $i++; continue }



        if ($ch -eq '(') { $toks.Add(@{type='lparen'; value='('}) | Out-Null; $i++; continue }

        if ($ch -eq ')') { $toks.Add(@{type='rparen'; value=')'}) | Out-Null; $i++; continue }



        $j = $i

        while ($j -lt $Expr.Length) {

            $c2 = $Expr[$j]

            if ([char]::IsWhiteSpace($c2) -or $c2 -eq '(' -or $c2 -eq ')') { break }

            $j++

        }

        $w = $Expr.Substring($i, $j-$i)

        $i = $j



        switch ($w) {

            'et'  { $toks.Add(@{type='and'; value='et'})  | Out-Null }

            'ou'  { $toks.Add(@{type='or';  value='ou'})  | Out-Null }

            'non' { $toks.Add(@{type='not'; value='non'}) | Out-Null }

            default { $toks.Add(@{type='word'; value=$w}) | Out-Null }

        }

    }

    return $toks.ToArray()

}



function Normalize-TagFilterForParse([string]$s) {

    if ([string]::IsNullOrWhiteSpace($s)) { return $s }

    $t = $s.Trim()



    # If user already used quotes or wrote a complex expression, keep as-is

    if ($t -match '"') { return $t }

    if ($t -match '[\(\)]') { return $t }

    if ($t -match '\b(and|or|not|et|ou|non)\b') { return $t }



    # If it contains spaces, treat as a single tag literal (tags may contain spaces, e.g. "little swa")

    if ($t -match '\s') {

        return '"' + ($t -replace '"','""') + '"'

    }

    return $t

}







function Parse-Expr([object[]]$Tokens) {

    $script:tok = $Tokens

    $script:pos = 0



    function Peek {

        if ($script:pos -ge $script:tok.Length) { return $null }

        return $script:tok[$script:pos]

    }



    function Eat([string]$type) {

        $p = Peek

        if ($null -eq $p -or $p.type -ne $type) { throw "Parse error: expected $type" }

        $script:pos++

        return $p

    }



    function ParsePrimary {

        $p = Peek

        if ($null -eq $p) { throw "Parse error: unexpected end" }



        if ($p.type -eq 'word')   { $script:pos++; return @{type='leaf'; value=$p.value} }

        if ($p.type -eq 'lparen') { Eat 'lparen' | Out-Null; $n = ParseOr; Eat 'rparen' | Out-Null; return $n }

        if ($p.type -eq 'not')    { Eat 'not'   | Out-Null; $inner = ParsePrimary; return @{type='not'; child=$inner} }



        throw "Parse error near token $($p.type)"

    }



    function ParseAnd {

        $left = ParsePrimary

        while ($true) {

            $p = Peek

            if ($null -ne $p -and $p.type -eq 'and') {

                Eat 'and' | Out-Null

                $right = ParsePrimary

                $left = @{type='and'; left=$left; right=$right}

            } else { break }

        }

        return $left

    }



    function ParseOr {

        $left = ParseAnd

        while ($true) {

            $p = Peek

            if ($null -ne $p -and $p.type -eq 'or') {

                Eat 'or' | Out-Null

                $right = ParseAnd

                $left = @{type='or'; left=$left; right=$right}

            } else { break }

        }

        return $left

    }



    $ast = ParseOr

    if ($script:pos -ne $script:tok.Length) {

        $rem = @()

        for ($k = $script:pos; $k -lt $script:tok.Length; $k++) {

            try { $rem += ("$($script:tok[$k].type):$($script:tok[$k].value)") } catch { $rem += "?" }

        }

        throw ("Parse error: trailing tokens at pos {0}/{1}: {2}" -f $script:pos, $script:tok.Length, ($rem -join ' | '))

    }

    return $ast

}



function Eval-Ast($Node, [scriptblock]$LeafEval) {

    switch ($Node.type) {

        'leaf' { return [bool](& $LeafEval $Node.value) }

        'not'  { return -not (Eval-Ast $Node.child $LeafEval) }

        'and'  { return (Eval-Ast $Node.left $LeafEval) -and (Eval-Ast $Node.right $LeafEval) }

        'or'   { return (Eval-Ast $Node.left $LeafEval) -or  (Eval-Ast $Node.right $LeafEval) }

        default { throw "Unknown node type '$($Node.type)'" }

    }

}



# Wildcard match helper (safe for deferred scriptblocks / WinForms handlers)

$script:WildcardMatchAnywhereImpl = {

    param([string]$Text, [string]$Pattern)



    $t = Safe-ToLower $Text

    $p = Safe-ToLower $Pattern

    if ($p -eq "") { return $true }



    # If user didn't include wildcards, match anywhere

    if ($p -notlike '*`**') { $p = "*" + $p + "*" }

    return ($t -like $p)

}



# --- Wildcard match helper (robust in events/closures; no self-recursion) ---

$script:WildcardMatchAnywhereImpl = {

    param([string]$Text, [string]$Pattern)



    $t = Safe-ToLower $Text

    $p = Safe-ToLower $Pattern



    if ($p -eq "") { return $true }



    # If user didn't include wildcards, match anywhere

    if ($p -notlike '*`**') { $p = "*" + $p + "*" }



    return ($t -like $p)

}



function Wildcard-MatchAnywhere {

    param([string]$Text, [string]$Pattern)

    return (& $script:WildcardMatchAnywhereImpl $Text $Pattern)

}



function WildCard-MatchAnywhere {

    param([string]$Text, [string]$Pattern)

    return (& $script:WildcardMatchAnywhereImpl $Text $Pattern)

}



function global:Wildcard-MatchAnywhere {

    param([string]$Text, [string]$Pattern)

    return (& $script:WildcardMatchAnywhereImpl $Text $Pattern)

}



function global:WildCard-MatchAnywhere {

    param([string]$Text, [string]$Pattern)

    return (& $script:WildcardMatchAnywhereImpl $Text $Pattern)

}



function Make-LeafEval-ForBody([string]$BodyText) {

    $b = Safe-ToLower $BodyText

    $sb = {

        param([string]$leaf)

        return (Wildcard-MatchAnywhere -Text $b -Pattern $leaf)

    }

    return $sb.GetNewClosure()

}



function Make-LeafEval-ForTags([string[]]$Tags) {

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($t in (Force-Array $Tags)) {

        $x = Safe-TrimLower $t

        if ($x -ne "") { [void]$set.Add($x) }

    }



    $sb = {

        param([string]$leaf)

        $l = Safe-TrimLower $leaf

        if ($l -eq "") { return $false }



        if ($l -eq "__EMPTY__") {

            # Fichiers sans tags

            return ($set.Count -eq 0)

        }



        if ($l -like '*`**') {

            foreach ($t in $set) {

                if ((Safe-ToLower $t) -like $l) { return $true }

            }

            return $false

        }

        return $set.Contains($l)

    }

    return $sb.GetNewClosure()

}



# ------------------------------ File types + search ------------------------------



$script:FileTypeOptions = @(

    [pscustomobject]@{ Label="Any file (*.*)"; Exts=@() }

    [pscustomobject]@{ Label="Archives (.7z,.rar,.zip,...)"; Exts=@(".7z",".rar",".zip",".tar",".gz",".bz2") }

    [pscustomobject]@{ Label="Audio files (.aac,.flac,.mp3,...)"; Exts=@(".aac",".flac",".m4a",".mp3",".ogg",".wav",".wma",".aiff",".alac") }

    [pscustomobject]@{ Label="Documents (.doc,.docx,.xls,...)"; Exts=@(".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pdf",".rtf",".odt",".ods",".odp",".csv",".txt",".md",".log",".nfo") }

    [pscustomobject]@{ Label="Executables/installers (.exe,.msi,...)"; Exts=@(".exe",".msi",".msix") }

    [pscustomobject]@{ Label="Images (.bmp,.gif,.jpg,.png,...)"; Exts=@(".bmp",".gif",".jpg",".jpeg",".png",".tif",".tiff",".webp",".heic",".cr2",".nef",".arw",".dng",".orf",".raf") }

    [pscustomobject]@{ Label="Subtitles (.srt,.ass,...)"; Exts=@(".srt",".ass",".ssa",".vtt") }

    [pscustomobject]@{ Label="Video files (.avi,.mp4,.wmv,...)"; Exts=@(".avi",".mkv",".mov",".mp4",".mpg",".mpeg",".wmv",".m4v",".webm",".flv") }

)

function Get-AllowedExtsFromChoice([string]$ChoiceLabel) {

    # Robust match: trim + case-insensitive, because ComboBox SelectedItem/Text can vary slightly.
    $cl = [string]$ChoiceLabel
    if ([string]::IsNullOrWhiteSpace($cl)) { return @() }
    $cln = ($cl.Trim()).ToLowerInvariant()

    foreach ($opt in $script:FileTypeOptions) {

        $ol = [string]$opt.Label
        if ([string]::IsNullOrWhiteSpace($ol)) { continue }
        if (($ol.Trim()).ToLowerInvariant() -eq $cln) { return [string[]]$opt.Exts }

    }

    # Fallback: allow matching by starts-with (useful if UI text slightly differs)
    foreach ($opt in $script:FileTypeOptions) {
        $ol = [string]$opt.Label
        if ([string]::IsNullOrWhiteSpace($ol)) { continue }
        $oln = ($ol.Trim()).ToLowerInvariant()
        if ($oln.StartsWith($cln)) { return [string[]]$opt.Exts }
        if ($cln.StartsWith($oln)) { return [string[]]$opt.Exts }
    }

    return @()

}


function Get-SelectedTypeLabel {
    param([System.Windows.Forms.ComboBox]$Combo)
    try {
        if ($null -eq $Combo) { return "" }
        $s = [string]$Combo.SelectedItem
        if ([string]::IsNullOrWhiteSpace($s)) { $s = [string]$Combo.Text }
        if ([string]::IsNullOrWhiteSpace($s) -and $Combo.Items -and $Combo.Items.Count -gt 0) {
            $s = [string]$Combo.Items[0]
        }
        return $s
    } catch {
        return ""
    }
}






# Human-readable file size (best unit)

function Format-FileSize([Int64]$Bytes) {

    if ($Bytes -lt 0) { return "" }

    if ($Bytes -lt 1024) { return ("{0} b" -f $Bytes) }

    $kb = [double]$Bytes / 1024.0

    if ($kb -lt 1024) { return ("{0:n0} kb" -f $kb) }

    $mb = $kb / 1024.0

    if ($mb -lt 1024) { return ("{0:n1} Mb" -f $mb) }

    $gb = $mb / 1024.0

    if ($gb -lt 1024) { return ("{0:n2} Gb" -f $gb) }

    $tb = $gb / 1024.0

    return ("{0:n2} Tb" -f $tb)

}

function Parse-SizeToBytes([string]$s) {
    # Accepts: "123", "10k", "10kb", "5m", "1.5g" (case-insensitive). Returns 0 if empty/invalid.
    try {
        if ([string]::IsNullOrWhiteSpace($s)) { return [int64]0 }
        $t = ($s.Trim()).ToLowerInvariant()
        $t = $t -replace ',', '.'

        $m = [regex]::Match($t, '^\s*(\d+(?:\.\d+)?)\s*([kmgt]?b?)\s*$')
        if (-not $m.Success) { return [int64]0 }

        $num = [double]::Parse($m.Groups[1].Value, [System.Globalization.CultureInfo]::InvariantCulture)
        $unit = $m.Groups[2].Value

        $mul = 1.0
        switch ($unit) {
            ''   { $mul = 1.0; break }
            'b'  { $mul = 1.0; break }
            'k'  { $mul = 1024.0; break }
            'kb' { $mul = 1024.0; break }
            'm'  { $mul = 1024.0*1024.0; break }
            'mb' { $mul = 1024.0*1024.0; break }
            'g'  { $mul = 1024.0*1024.0*1024.0; break }
            'gb' { $mul = 1024.0*1024.0*1024.0; break }
            't'  { $mul = 1024.0*1024.0*1024.0*1024.0; break }
            'tb' { $mul = 1024.0*1024.0*1024.0*1024.0; break }
            default { $mul = 1.0; break }
        }

        $bytes = [int64][math]::Floor($num * $mul)
        if ($bytes -lt 0) { return [int64]0 }
        return $bytes
    } catch {
        return [int64]0
    }
}




# Extension -> file type label lookup (for per-file "File type" column)

$script:ExtToTypeLabel = @{}

foreach ($opt in $script:FileTypeOptions) {

    if ($opt.Label -eq "Any file (*.*)") { continue }

    foreach ($e in (Force-Array $opt.Exts)) {

        $le = Safe-ToLower ([string]$e)

        if ($le -ne "" -and -not $script:ExtToTypeLabel.ContainsKey($le)) {

            $script:ExtToTypeLabel[$le] = [string]$opt.Label

        }

    }

}

function Get-FileTypeLabelFromPath([string]$Path) {
    $ext = ""
    try {
        $ext = Safe-ToLower ([System.IO.Path]::GetExtension($Path))
        if ($ext -ne "" -and $script:ExtToTypeLabel.ContainsKey($ext)) { return [string]$script:ExtToTypeLabel[$ext] }
    } catch {}
    if ([string]::IsNullOrWhiteSpace($ext)) { return "Other (no extension)" }
    return ("Other ({0})" -f $ext)
}





function Search-Files {

    param(

        [string]  $Dir,

        [bool]    $UseBody,

        [string]  $BodyFilter,

        [bool]    $UseTag,

        [string]  $TagFilter,

        [string[]]$AllowedExts,

        [Int64]   $MinSizeBytes = 0,

        [Int64]   $MaxSizeBytes = 0,

        [bool]    $NoSubdirs = $false,

        [Nullable[datetime]]$ModifiedAfter = $null,

        [Nullable[datetime]]$ModifiedBefore = $null,

        [scriptblock]$CancelCheck,
        [switch]$ForceRefresh

    )

$bodyAst = $null

    $tagAst  = $null



    if ($UseBody -and -not [string]::IsNullOrWhiteSpace($BodyFilter)) {

        $bt = Tokenize-Expr $BodyFilter

        if ((Get-Count $bt) -gt 0) {

            $bodyAst = Parse-Expr $bt

        }

    }



    if ($UseTag) {

        if ([string]::IsNullOrWhiteSpace($TagFilter)) {

            # Tag filter vide => fichiers sans tags

            $tagAst = @{ type='leaf'; value='__EMPTY__' }

        } else {

            $TagFilter = Normalize-TagFilterForParse $TagFilter

            $tt = Tokenize-Expr $TagFilter

            if ((Get-Count $tt) -gt 0) {

                $tagAst = Parse-Expr $tt

            }

        }

    }



        $extAllowed = @()
    if ((Get-Count $AllowedExts) -gt 0) {
        $extAllowed = @(
            $AllowedExts | ForEach-Object {
                $e = [string]$_
                if ([string]::IsNullOrWhiteSpace($e)) { return }
                $e = $e.Trim()
                if ($e -notmatch '^\.') { $e = '.' + $e }
                Safe-ToLower $e
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
        )
    }

# File enumeration (optimized for network shares):
# - On network paths, we build a cached full index once, then filter locally by extension / tags / body.
#   This makes subsequent searches (changing type/filters) much faster.
# - On local disks, we keep the standard traversal (no caching).
$files = $null
$extFiltered = $false
if ($NoSubdirs) {
    $allIndex = $null  # NoSubdirs does not need cached recursive index
} else {
    $allIndex = Get-OrBuild-DirFileIndex -Dir $Dir -CancelCheck $CancelCheck -ForceRefresh:$ForceRefresh
}
if ($null -ne $allIndex) {

    if ((Get-Count $extAllowed) -gt 0) {

        $hs = $null
        try {
            $hs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($e in $extAllowed) {
                if (-not [string]::IsNullOrWhiteSpace($e)) { [void]$hs.Add($e) }
            }
        } catch { $hs = $null }

        if ($null -ne $hs) {
            $tmp = New-Object System.Collections.Generic.List[System.IO.FileInfo]
            foreach ($fi in $allIndex) {
                if ($CancelCheck -and (& $CancelCheck)) { break }
                try { if (-not $hs.Contains($fi.Extension)) { continue } } catch { continue }
                [void]$tmp.Add($fi)
            }
            $files = $tmp.ToArray()
            $extFiltered = $true
        } else {
            $files = @($allIndex)
        }

    } else {

        $files = @($allIndex)

    }

} else {

    $files = Get-FilesRecursiveSafe -Dir $Dir -AllowedExtsLower $extAllowed -CancelCheck $CancelCheck -NoSubdirs:([bool]$NoSubdirs)

}


    # Ensure extension filtering is applied consistently (including NoSubdirs / non-cached enumeration).
    if (-not $extFiltered -and (Get-Count $extAllowed) -gt 0 -and $null -ne $files) {
        $hs2 = $null
        try {
            $hs2 = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($e in $extAllowed) { if (-not [string]::IsNullOrWhiteSpace($e)) { [void]$hs2.Add([string]$e) } }
        } catch { $hs2 = $null }

        if ($null -ne $hs2) {
            $tmp2 = New-Object System.Collections.Generic.List[System.IO.FileInfo]
            foreach ($fi in $files) {
                if ($CancelCheck -and (& $CancelCheck)) { break }
                try {
                    if (-not $hs2.Contains($fi.Extension)) { continue }
                } catch { continue }
                [void]$tmp2.Add($fi)
            }
            $files = $tmp2.ToArray()
            $extFiltered = $true
        }
    }




    $out = New-Object System.Collections.Generic.List[object]

    foreach ($f in $files) {

        if ($null -eq $f) { continue }

        if ($CancelCheck -and (& $CancelCheck)) { break }

$nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)

        $body   = Get-BodyFromNameNoExt $nameNoExt

        $tagsArr = Normalize-Tags (Get-TagsFromNameNoExt $nameNoExt)



        if ($UseBody -and $null -ne $bodyAst) {

            $leaf = Make-LeafEval-ForBody $body

            if (-not (Eval-Ast $bodyAst $leaf)) { continue }

        }



        if ($UseTag -and $null -ne $tagAst) {

            if ($tagAst.type -eq 'leaf' -and $tagAst.value -eq '__EMPTY__') {

                if ((Get-Count $tagsArr) -gt 0) { continue }

            } else {

                $leaf = Make-LeafEval-ForTags $tagsArr

                if (-not (Eval-Ast $tagAst $leaf)) { continue }

            }

        }



        $created = $null

        try { $created = $f.CreationTime } catch { $created = $null }

$lastMod = $null

try { $lastMod = $f.LastWriteTime } catch { $lastMod = $null }



$sizeBytes = 0

try { $sizeBytes = [Int64]$f.Length } catch { $sizeBytes = 0 }




        # --- Size / date filters (applied early) ---
        if ($MinSizeBytes -gt 0 -and $sizeBytes -lt $MinSizeBytes) { continue }
        if ($MaxSizeBytes -gt 0 -and $sizeBytes -gt $MaxSizeBytes) { continue }

        if ($null -ne $ModifiedAfter -and $lastMod -ne $null) {
            $ma = [datetime]$ModifiedAfter
            if ($lastMod -lt $ma) { continue }
        }
        if ($null -ne $ModifiedBefore -and $lastMod -ne $null) {
            $mb = [datetime]$ModifiedBefore
            if ($lastMod -gt $mb) { continue }
        }


$ftLabel = Get-FileTypeLabelFromPath $f.FullName





        # Affichage des tags : "a,b c,d" (mais sur disque on reste en " + ")

        $tagsDisplay = ""

        if ((Get-Count $tagsArr) -gt 0) {

            $tagsDisplay = ($tagsArr -join ",")

        }



        $obj = [PSCustomObject]@{

            Path         = $f.FullName

            Created      = $created

            LastModified = $lastMod

            SizeBytes    = $sizeBytes

            Size         = (Format-FileSize $sizeBytes)

            FileType     = $ftLabel

            Body         = $body

            Tags         = $tagsDisplay

            TagCount     = (Get-Count $tagsArr)

        }

        [void]$out.Add($obj)

    }



    return $out.ToArray()

}




function Search-PathsNoSubdirsection {
    param(
        [string[]]$Paths,
        [bool]    $UseBody,
        [string]  $BodyFilter,
        [bool]    $UseTag,
        [string]  $TagFilter,
        [string[]]$AllowedExts,
        [Int64]   $MinSizeBytes = 0,
        [Int64]   $MaxSizeBytes = 0,
        [Nullable[datetime]]$ModifiedAfter = $null,
        [Nullable[datetime]]$ModifiedBefore = $null,
        [scriptblock]$CancelCheck
    )

    $out = New-Object System.Collections.Generic.List[object]

    $bodyAst = $null
    $tagAst  = $null

    if ($UseBody -and -not [string]::IsNullOrWhiteSpace($BodyFilter)) {
        $bt = Tokenize-Expr $BodyFilter
        if ((Get-Count $bt) -gt 0) { $bodyAst = Parse-Expr $bt }
    }

    if ($UseTag) {
        if ([string]::IsNullOrWhiteSpace($TagFilter)) {
            $tagAst = @{ type='leaf'; value='__EMPTY__' }
        } else {
            $tt = Tokenize-Expr $TagFilter
            if ((Get-Count $tt) -gt 0) { $tagAst = Parse-Expr $tt }
        }
    }

    $extAllowed = @()
    if ((Get-Count $AllowedExts) -gt 0) { $extAllowed = @($AllowedExts | ForEach-Object { Safe-ToLower $_ }) }

    foreach ($p in @($Paths)) {
        if ($CancelCheck -and (& $CancelCheck)) { break }
        if ([string]::IsNullOrWhiteSpace($p)) { continue }

        $f = $null
        try { $f = [System.IO.FileInfo]$p } catch { $f = $null }
        if ($null -eq $f) { continue }
        try { if (-not $f.Exists) { continue } } catch { continue }

        if ((Get-Count $extAllowed) -gt 0) {
            try {
                $ext = Safe-ToLower $f.Extension
                if (-not $extAllowed.Contains($ext)) { continue }
            } catch { continue }
        }

        $created = $null
        try { $created = $f.CreationTime } catch { $created = $null }

        $lastMod = $null
        try { $lastMod = $f.LastWriteTime } catch { $lastMod = $null }

        $sizeBytes = 0
        try { $sizeBytes = [Int64]$f.Length } catch { $sizeBytes = 0 }

        if ($MinSizeBytes -gt 0 -and $sizeBytes -lt $MinSizeBytes) { continue }
        if ($MaxSizeBytes -gt 0 -and $sizeBytes -gt $MaxSizeBytes) { continue }

        if ($null -ne $ModifiedAfter -and $lastMod -ne $null) {
            $ma = [datetime]$ModifiedAfter
            if ($lastMod -lt $ma) { continue }
        }
        if ($null -ne $ModifiedBefore -and $lastMod -ne $null) {
            $mb = [datetime]$ModifiedBefore
            if ($lastMod -gt $mb) { continue }
        }

        $nameNoExt = $null
        try { $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($f.Name) } catch { $nameNoExt = "" }

        $body = Get-BodyFromNameNoExt $nameNoExt
        $tagsArr = Normalize-Tags (Get-TagsFromNameNoExt $nameNoExt)

        if ($UseBody -and $null -ne $bodyAst) {
            $leaf = Make-LeafEval-ForBody $body
            if (-not (Eval-Ast $bodyAst $leaf)) { continue }
        }

        if ($UseTag -and $null -ne $tagAst) {
            if ($tagAst.type -eq 'leaf' -and $tagAst.value -eq '__EMPTY__') {
                if ((Get-Count $tagsArr) -gt 0) { continue }
            } else {
                $leaf = Make-LeafEval-ForTags $tagsArr
                if (-not (Eval-Ast $tagAst $leaf)) { continue }
            }
        }

        $ftLabel = Get-FileTypeLabelFromPath $f.FullName

        $tagsDisplay = ""
        try { $tagsDisplay = (Format-TagsForDisplay $tagsArr) } catch { $tagsDisplay = "" }

        $obj = [PSCustomObject]@{
            Path         = $f.FullName
            Created      = $created
            LastModified = $lastMod
            SizeBytes    = $sizeBytes
            Size         = (Format-FileSize $sizeBytes)
            FileType     = $ftLabel
            Body         = $body
            Tags         = $tagsDisplay
            TagCount     = (Get-Count $tagsArr)
        }

        [void]$out.Add($obj)
    }

    return $out.ToArray()
}

# ------------------------------ Tags found list ------------------------------



function Scan-AllTagsInDir([string]$Dir, [string[]]$AllowedExts) {

    if ([string]::IsNullOrWhiteSpace($Dir) -or -not (Test-Path -LiteralPath $Dir)) { return @() }



        $extAllowed = @()
    if ((Get-Count $AllowedExts) -gt 0) {
        $extAllowed = @(
            $AllowedExts | ForEach-Object {
                $e = [string]$_
                if ([string]::IsNullOrWhiteSpace($e)) { return }
                $e = $e.Trim()
                if ($e -notmatch '^\.') { $e = '.' + $e }
                Safe-ToLower $e
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
        )
    }

$set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    $files = Get-FilesRecursiveSafe -Dir $Dir

    foreach ($f in $files) {

        if ((Get-Count $extAllowed) -gt 0) {

            $ext = Safe-ToLower $f.Extension

            if (-not ($extAllowed -contains $ext)) { continue }

        }

        try {

            $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)

            $tags = Normalize-Tags (Get-TagsFromNameNoExt $nameNoExt)

            foreach ($t in $tags) { [void]$set.Add($t) }

        } catch {}

    }

    return @($set | Sort-Object)

}



# ------------------------------ Settings persistence ------------------------------



$script:AppName = "TagBrowser"

# ------------------------------ UI ------------------------------



[System.Windows.Forms.Application]::EnableVisualStyles()



$form = New-Object System.Windows.Forms.Form

$script:FormMain = $form
$form.Text = "Tag browser"

# Settings: restore on first Shown; save on close (strict)
if (-not (Get-Variable -Name _SettingsHooked -Scope Script -ErrorAction SilentlyContinue)) { $script:_SettingsHooked = $false }
if (-not $script:_SettingsHooked) {
    $script:_SettingsHooked = $true
    try {
        $form.Add_Shown({
            if (-not $script:_SettingsRestoredOnce) {
                $script:_SettingsRestoredOnce = $true
                Restore-Settings
            }
        })
        $form.Add_FormClosing({
            try {
                _Dbg "FormClosing: saving settings..."
                Save-Settings
            } catch { }
        })
    } catch { }
}


$form.StartPosition = "CenterScreen"

$form.Size = New-Object System.Drawing.Size(1200, 760)

$form.MinimumSize = New-Object System.Drawing.Size(980, 640)

$form.Padding = New-Object System.Windows.Forms.Padding(10)




# Allow form-level key handling (Esc to interrupt search)
$form.KeyPreview = $true
$form.Add_KeyDown({
    param($sender,$e)
    try {

        # ESC cancels an ongoing search
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
            if ($script:IsSearching) {
                Request-InterruptSearch
                $e.SuppressKeyPress = $true
                $e.Handled = $true
                return
            }
            elseif ($script:IsHashingDuplicates -and $script:DupWorker -and $script:DupWorker.IsBusy) {
                try { Cancel-DuplicateWorker } catch { }
                $e.SuppressKeyPress = $true
                $e.Handled = $true
                return
            }
        }

        # F5 forces a rescan (refresh scan cache) with current criteria
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::F5) {
            try { Trigger-Search -ForceRefresh } catch { }
            $e.SuppressKeyPress = $true
            $e.Handled = $true
            return
        }

        # Ctrl+Y opens search history
        if ($e.Control -and ($e.KeyCode -eq [System.Windows.Forms.Keys]::Y)) {
            try { Show-SearchHistoryDialog } catch { }
            $e.SuppressKeyPress = $true
            $e.Handled = $true
            return
        }

    } catch { }
})
# Status bar (added LAST to ensure it stays visible at the very bottom)

$status = New-Object System.Windows.Forms.StatusStrip
$status.SizingGrip = $true
$status.Visible = $true

$stMsg = New-Object System.Windows.Forms.ToolStripStatusLabel
$stMsg.Spring = $true
$stMsg.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$stMsg.Text = ""

$stInfo = New-Object System.Windows.Forms.ToolStripStatusLabel
$stInfo.Spring = $false
$stInfo.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$stInfo.Text = "Ready"
$stEverything = New-Object System.Windows.Forms.ToolStripStatusLabel
$stEverything.Spring = $false
$stEverything.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$stProg = New-Object System.Windows.Forms.ToolStripProgressBar
$stProg.Visible = $false
$stProg.Minimum = 0
$stProg.Maximum = 100
$stProg.Value = 0
$stProg.AutoSize = $false
$stProg.Width = 140
$stProg.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
$stProg.MarqueeAnimationSpeed = 25

$stPct = New-Object System.Windows.Forms.ToolStripStatusLabel
$stPct.Visible = $false
$stPct.Spring = $false
$stPct.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$stPct.Text = ""

$stEverything.Text = "Everything: off"


[void]$status.Items.Add($stMsg)
$status.Items.Add($stProg)
$status.Items.Add($stPct)
[void]$status.Items.Add($stEverything)
[void]$status.Items.Add($stInfo)
$form.Controls.Add($status)

function Set-Status([string]$msg) {
    try {
        if ($null -ne $stMsg) { $stMsg.Text = $msg }
    } catch {}
}


function Set-OpStatus([string]$msg) {
    # Operation summary (e.g., changed/skipped/failed) that should survive a view refresh.
    try { $script:LastOpStatusLeft = $msg } catch { }
    Set-Status $msg
}

function Clear-OpStatus {
    try { $script:LastOpStatusLeft = "" } catch { }
}

function Set-Info([string]$msg) {
    # Right status text (activity)
    try {
        if ($null -ne $stInfo) { $stInfo.Text = $msg }
    } catch { }
}
function Set-ProgressUI {
    param(
        [Nullable[int]]$Percent,
        [switch]$Marquee,
        [string]$Text = ""
    )
    if (-not $form -or -not $status) { return }

    $apply = {
        param($p,$m,$t)
        try {
            if ($m) {
                $stProg.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
                $stProg.MarqueeAnimationSpeed = 25
            } else {
                $stProg.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
                $stProg.MarqueeAnimationSpeed = 0
            }

            if ($p -ne $null) {
                $pp = [Math]::Max(0, [Math]::Min(100, [int]$p))
                $stProg.Value = $pp
                $stPct.Text = "$pp`%"
                $stPct.Visible = $true
            } else {
                $stPct.Text = ""
                $stPct.Visible = $false
            }

            if (-not [string]::IsNullOrWhiteSpace($t)) {
                $stInfo.Text = $t
            } else {
                $stInfo.Text = ""
            }

            $stProg.Visible = $true
        } catch {
            # Never let progress UI crash the app
        }
    }

    try {
        if ($form.InvokeRequired) {
            $form.BeginInvoke($apply, @($Percent, [bool]$Marquee, $Text)) | Out-Null
        } else {
            & $apply $Percent ([bool]$Marquee) $Text
        }
    } catch {
        # ignore
    }
}

function Start-Progress {
    param([string]$Text = "", [switch]$Marquee)
    Set-ProgressUI -Percent $null -Marquee:$Marquee -Text $Text
}

function Update-Progress {
    param([int]$Percent, [string]$Text = "")
    Set-ProgressUI -Percent $Percent -Marquee:$false -Text $Text
}

function Stop-Progress {
    if (-not $form -or -not $status) { return }
    $apply = {
        try {
            $stProg.Visible = $false
            $stPct.Visible = $false
            $stPct.Text = ""
            $stProg.Value = 0
            $stProg.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
            $stProg.MarqueeAnimationSpeed = 25
        } catch {}
    }
    try {
        if ($form.InvokeRequired) { $form.BeginInvoke($apply) | Out-Null } else { & $apply }
    } catch {}
}

function Ensure-FormFitsScreen {
    param([System.Windows.Forms.Form]$F)

    if (-not $F) { return }

    try {
        $wa = [System.Windows.Forms.Screen]::FromControl($F).WorkingArea
    } catch {
        $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    }

    try {
        $b = $F.Bounds

        # Clamp size first
        if ($b.Width -gt $wa.Width)  { $b.Width  = [Math]::Max(400, $wa.Width  - 20) }
        if ($b.Height -gt $wa.Height){ $b.Height = [Math]::Max(300, $wa.Height - 20) }

        # Clamp position
        if ($b.X -lt $wa.X) { $b.X = $wa.X }
        if ($b.Y -lt $wa.Y) { $b.Y = $wa.Y }

        if (($b.X + $b.Width) -gt ($wa.X + $wa.Width)) {
            $b.X = [Math]::Max($wa.X, ($wa.X + $wa.Width) - $b.Width)
        }
        if (($b.Y + $b.Height) -gt ($wa.Y + $wa.Height)) {
            $b.Y = [Math]::Max($wa.Y, ($wa.Y + $wa.Height) - $b.Height)
        }

        $F.Bounds = $b
    } catch {
        # ignore
    }
}



function Set-EverythingInfo([string]$msg) {
    # Middle-right status text (Everything indicator)
    try {
        if ($null -ne $stEverything) { $stEverything.Text = $msg }
    } catch { }
}

function Get-EverythingStatusText {
    try {
        $es = Get-Command es.exe -ErrorAction SilentlyContinue
        if (-not $es) { return "Everything: ES not found" }
        $p = Get-Process -Name Everything -ErrorAction SilentlyContinue
        if (-not $p) { return "Everything: not running" }
        return "Everything: OK"
    } catch {
        return "Everything: unknown"
    }
}




function Show-Status([string]$msg) {
    # Compatibility helper (older code used Show-Status)
    Set-Status $msg
}

function Get-DisplayedRowCount {
    try {
        $n = 0
        if ($null -ne $grid -and $null -ne $grid.Rows) {
            foreach ($r in @($grid.Rows)) {
                if (-not $r.IsNewRow -and $r.Visible) { $n++ }
            }
            return $n
        }
    } catch { }
    try { return (Get-Count $script:CurrentItems) } catch { return 0 }
}

function Update-FoundCountStatus {
    param(
        [switch]$UpdatingView
    )
    # Update left status text with the number of rows currently displayed in the grid.
    # If an operation summary exists, keep it and append the displayed count.
    try {
        $n = Get-DisplayedRowCount

        $base = ""
        try { $base = [string]$script:LastOpStatusLeft } catch { $base = "" }

        if (-not [string]::IsNullOrWhiteSpace($base)) {
            Set-Status ("{0} | Displayed: {1} file(s)" -f $base, $n)
            return
        }

        if ($UpdatingView) {
            Set-Status ("Displayed: {0} file(s)" -f $n)
            return
        }

        Set-Status ("Search: {0} file(s) found" -f $n)
    } catch {
        try {
            $fallback = 0
            try { $fallback = (Get-Count $script:CurrentItems) } catch { $fallback = 0 }
            if ($UpdatingView) {
                Set-Status ("Displayed: {0} file(s)" -f $fallback)
            } else {
                Set-Status ("Search: {0} file(s) found" -f $fallback)
            }
        } catch { }
    }
}


# GroupBoxes : Search (top), Results (fill), Actions (bottom)

# IMPORTANT: docking in WinForms depends on control order (z-order).

# We add Fill FIRST, then Top/Bottom, and the StatusStrip LAST.



$gbResults = New-Object System.Windows.Forms.GroupBox

$gbResults.Text = "Results"

$gbResults.Dock = "Fill"

# give breathing room so DataGridView headers aren't clipped by the GroupBox border/title

$gbResults.Padding = New-Object System.Windows.Forms.Padding(10, 22, 10, 10)

$form.Controls.Add($gbResults)



$gbSearch = New-Object System.Windows.Forms.GroupBox

$gbSearch.Text = "Search"

$gbSearch.Height = 142
$gbSearch.Dock = "Top"

$gbSearch.Padding = New-Object System.Windows.Forms.Padding(10, 22, 10, 10)

$form.Controls.Add($gbSearch)



$gbActions = New-Object System.Windows.Forms.GroupBox

$gbActions.Text = "Actions"

$gbActions.Height = 86

$gbActions.Dock = "Fill"

$gbActions.Padding = New-Object System.Windows.Forms.Padding(10, 22, 10, 10)



# Bottom container: ensures StatusStrip is ALWAYS below Actions (fixes docking/z-order glitches)

$panelBottom = New-Object System.Windows.Forms.Panel

$panelBottom.Dock = "Bottom"

$panelBottom.Height = ($gbActions.Height + 26)

$panelBottom.Padding = New-Object System.Windows.Forms.Padding(0)



# StatusStrip must be at the very bottom of the bottom panel

$status.Dock = "Bottom"



[void]$panelBottom.Controls.Add($gbActions)

[void]$panelBottom.Controls.Add($status)



[void]$form.Controls.Add($panelBottom)

# --- Search controls (layout identique à la version stable que tu avais validée)



$lblDir = New-Object System.Windows.Forms.Label

$lblDir.Text = "Directory"

$lblDir.AutoSize = $true

$lblDir.Location = New-Object System.Drawing.Point(10, 24)

$gbSearch.Controls.Add($lblDir)



$txtDir = New-Object System.Windows.Forms.ComboBox
$txtDir.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
$txtDir.AutoCompleteMode = [System.Windows.Forms.AutoCompleteMode]::SuggestAppend
$txtDir.AutoCompleteSource = [System.Windows.Forms.AutoCompleteSource]::ListItems
$txtDir.Location = New-Object System.Drawing.Point(70, 20)
$txtDir.Width = 610
$txtDir.Anchor = "Top,Left"  # layout handled by Update-SearchLayout to avoid overlap
$gbSearch.Controls.Add($txtDir)

$chkNoSubdirs = New-Object System.Windows.Forms.CheckBox
$chkNoSubdirs.Text = "No subdirs"
$chkNoSubdirs.AutoSize = $true
$chkNoSubdirs.Location = New-Object System.Drawing.Point(690, 22)
$chkNoSubdirs.Anchor = "Top,Left"
$gbSearch.Controls.Add($chkNoSubdirs)

# Enter in Directory triggers search
$txtDir.Add_KeyDown({
    param($sender, $e)
    try {
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $e.SuppressKeyPress = $true
            Trigger-Search
        }
    } catch { }
})
$btnBrowse = New-Object System.Windows.Forms.Button

$btnBrowse.Text = "Br&owse (Ctrl+O)"

$btnBrowse.UseMnemonic = $true
$btnBrowse.Location = New-Object System.Drawing.Point(800, 18)

$btnBrowse.Size = New-Object System.Drawing.Size(110, 26)

$btnBrowse.Anchor = "Top,Right"

$gbSearch.Controls.Add($btnBrowse)

# Keep controls from overlapping when the window is resized
function Update-SearchLayout {
    try {
        $marginRight = 10
        $gap = 8

        # --- Directory row ---
        if ($btnBrowse -and $gbSearch) {
            $btnBrowse.Left = $gbSearch.ClientSize.Width - $btnBrowse.Width - $marginRight
        }
        if ($chkNoSubdirs -and $btnBrowse) {
            $chkNoSubdirs.Left = $btnBrowse.Left - $chkNoSubdirs.Width - $gap
        }
        if ($txtDir -and $chkNoSubdirs) {
            $newW = $chkNoSubdirs.Left - $txtDir.Left - $gap
            if ($newW -lt 120) { $newW = 120 }
            $txtDir.Width = $newW
        }

        # --- Everything checkbox: right after 'Before' date on the same row ---
        if ($chkEverything -and $dtBefore -and $gbSearch) {
            $chkEverything.Top = $dtBefore.Top + 2
            $x = $dtBefore.Right + $gap
            $maxLeft = $gbSearch.ClientSize.Width - $chkEverything.Width - $marginRight
            if ($x -gt $maxLeft) { $x = $maxLeft }
            if ($x -lt 10) { $x = 10 }
            $chkEverything.Left = $x
        }

        # --- Right-side buttons (keep visible regardless of window width) ---
        if ($gbSearch) {
            $btnX = $gbSearch.ClientSize.Width - $marginRight
            foreach ($b in @($btnSearch, $btnRescan, $btnHistory)) {
                if ($b) { $b.Left = [Math]::Max(10, $btnX - $b.Width) }
            }
        }
    } catch { }
}

# Reflow on resize + at startup
$gbSearch.Add_Resize({ Update-SearchLayout })
$form.Add_Resize({ Update-SearchLayout })
Update-SearchLayout

# Ensure layout is correct once the form is actually shown (ClientSize is final then)
$form.Add_Shown({
    try {
        $form.BeginInvoke([Action]{
            Update-SearchLayout
            if ($chkNoSubdirs) { $chkNoSubdirs.Visible = $true; $chkNoSubdirs.BringToFront() }
            if ($chkEverything) { $chkEverything.Visible = $true; $chkEverything.BringToFront() }
        }) | Out-Null
    } catch { }
})




$chkBody = New-Object System.Windows.Forms.CheckBox

$chkBody.Text = "Body"

$chkBody.AutoSize = $true

$chkBody.Location = New-Object System.Drawing.Point(10, 52)

$gbSearch.Controls.Add($chkBody)



$txtBody = New-Object System.Windows.Forms.TextBox

$txtBody.Location = New-Object System.Drawing.Point(70, 50)

$txtBody.Width = 420

$txtBody.Anchor = "Top,Left"

$gbSearch.Controls.Add($txtBody)



$btnResetBody = New-Object System.Windows.Forms.Button

$btnResetBody.Text = "X"

$btnResetBody.Location = New-Object System.Drawing.Point(495, 48)

$btnResetBody.Size = New-Object System.Drawing.Size(28, 26)

$btnResetBody.Anchor = "Top,Right"

$gbSearch.Controls.Add($btnResetBody)



$lblTypes = New-Object System.Windows.Forms.Label

$lblTypes.Text = "File types"

$lblTypes.AutoSize = $true

$lblTypes.Location = New-Object System.Drawing.Point(530, 54)

$gbSearch.Controls.Add($lblTypes)



$comboTypes = New-Object System.Windows.Forms.ComboBox

$comboTypes.DropDownStyle = "DropDownList"

$comboTypes.Location = New-Object System.Drawing.Point(600, 50)

$comboTypes.Width = 250

$comboTypes.Anchor = "Top,Left,Right"

$gbSearch.Controls.Add($comboTypes)




# Auto-refresh search when file type changes (guarded during initialization).
$comboTypes.add_SelectedIndexChanged({
    try {
        if ($script:IsInitializing) { return }
        Trigger-Search
    } catch { }
})

$chkTag = New-Object System.Windows.Forms.CheckBox

$chkTag.Text = "Tag"

$chkTag.AutoSize = $true

$chkTag.Location = New-Object System.Drawing.Point(10, 82)

$chkTag.Checked = $false

$gbSearch.Controls.Add($chkTag)



$txtTag = New-Object System.Windows.Forms.TextBox

$txtTag.Location = New-Object System.Drawing.Point(70, 80)

$txtTag.Width = 420

$txtTag.Anchor = "Top,Left"

$gbSearch.Controls.Add($txtTag)



$btnResetTag = New-Object System.Windows.Forms.Button

$btnResetTag.Text = "X"

$btnResetTag.Location = New-Object System.Drawing.Point(495, 78)

$btnResetTag.Size = New-Object System.Drawing.Size(28, 26)

$btnResetTag.Anchor = "Top,Right"

$gbSearch.Controls.Add($btnResetTag)



$lblFound = New-Object System.Windows.Forms.Label

$lblFound.Text = "Tags found"

$lblFound.AutoSize = $true

$lblFound.Location = New-Object System.Drawing.Point(530, 84)

$gbSearch.Controls.Add($lblFound)



$comboFoundTags = New-Object System.Windows.Forms.ComboBox

$comboFoundTags.DropDownStyle = "DropDownList"

$comboFoundTags.Location = New-Object System.Drawing.Point(600, 80)

$comboFoundTags.Width = 250

$comboFoundTags.Anchor = "Top,Left,Right"

$gbSearch.Controls.Add($comboFoundTags)

# --- Advanced filters (size/date/size/date) + Everything option ---
$lblMinSize = New-Object System.Windows.Forms.Label
$lblMinSize.Text = "Min size:"
$lblMinSize.AutoSize = $true
$lblMinSize.Location = New-Object System.Drawing.Point(10, 114)
$gbSearch.Controls.Add($lblMinSize)

$txtMinSize = New-Object System.Windows.Forms.TextBox
$txtMinSize.Location = New-Object System.Drawing.Point(70, 110)
$txtMinSize.Width = 60
$gbSearch.Controls.Add($txtMinSize)

$lblMaxSize = New-Object System.Windows.Forms.Label
$lblMaxSize.Text = "Max size:"
$lblMaxSize.AutoSize = $true
$lblMaxSize.Location = New-Object System.Drawing.Point(140, 114)
$gbSearch.Controls.Add($lblMaxSize)

$txtMaxSize = New-Object System.Windows.Forms.TextBox
$txtMaxSize.Location = New-Object System.Drawing.Point(205, 110)
$txtMaxSize.Width = 60
$gbSearch.Controls.Add($txtMaxSize)

$lblAfter = New-Object System.Windows.Forms.Label
$lblAfter.Text = "After:"
$lblAfter.AutoSize = $true
$lblAfter.Location = New-Object System.Drawing.Point(275, 114)
$gbSearch.Controls.Add($lblAfter)

$dtAfter = New-Object System.Windows.Forms.DateTimePicker
$dtAfter.Format = [System.Windows.Forms.DateTimePickerFormat]::Short
$dtAfter.ShowCheckBox = $true
$dtAfter.Checked = $false
$dtAfter.Location = New-Object System.Drawing.Point(320, 110)
$dtAfter.Width = 120
$gbSearch.Controls.Add($dtAfter)

$lblBefore = New-Object System.Windows.Forms.Label
$lblBefore.Text = "Before:"
$lblBefore.AutoSize = $true
$lblBefore.Location = New-Object System.Drawing.Point(450, 114)
$gbSearch.Controls.Add($lblBefore)

$dtBefore = New-Object System.Windows.Forms.DateTimePicker
$dtBefore.Format = [System.Windows.Forms.DateTimePickerFormat]::Short
$dtBefore.ShowCheckBox = $true
$dtBefore.Checked = $false
$dtBefore.Location = New-Object System.Drawing.Point(505, 110)
$dtBefore.Width = 120
$gbSearch.Controls.Add($dtBefore)


# Enter in advanced filters triggers search (controls exist at this point)
try {
    if ($txtMinSize) { $txtMinSize.Add_KeyDown($__enterTriggersSearch) }
    if ($txtMaxSize) { $txtMaxSize.Add_KeyDown($__enterTriggersSearch) }
    if ($dtAfter)    { $dtAfter.Add_KeyDown($__enterTriggersSearch) }
    if ($dtBefore)   { $dtBefore.Add_KeyDown($__enterTriggersSearch) }
} catch { }

$chkEverything = New-Object System.Windows.Forms.CheckBox
$chkEverything.Text = "Use Everything (fast)"
$chkEverything.AutoSize = $true
$chkEverything.Location = New-Object System.Drawing.Point(635, 112)  # placed after "Before" date, refined by Update-SearchLayout
$chkEverything.Anchor = "Top,Left"
$gbSearch.Controls.Add($chkEverything)
Update-SearchLayout  # ensure proper placement (after dtBefore exists)

$chkEverything.Add_CheckedChanged({
    try {
        if (-not $script:EverythingHintShown) { $script:EverythingHintShown = $false }

        if ($chkEverything.Checked) {

            $status = Get-EverythingStatusText
            Set-EverythingInfo $status

            if ($status -eq "Everything: ES not found") {
                if (-not $script:EverythingHintShown) {
                    $script:EverythingHintShown = $true
                    [System.Windows.Forms.MessageBox]::Show(
                        "Everything is not configured on this PC.`r`n`r`n" +
                        "To enable fast network searches:`r`n" +
                        "1) Install Everything (Voidtools) and start it.`r`n" +
                        "2) Install ES (Everything CLI) (es.exe).`r`n" +
                        "   - Download ES (Everything CLI) from voidtools.com`r`n" +
                        "   - Put es.exe in a folder present in PATH, or next to this script.`r`n`r`n" +
                        "Then restart this app and check 'Use Everything (fast)' again.",
                        "Everything / ES not found",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    ) | Out-Null
                }
                $chkEverything.Checked = $false
                return
            }

            if ($status -eq "Everything: not running") {
                if (-not $script:EverythingHintShown) {
                    $script:EverythingHintShown = $true
                    [System.Windows.Forms.MessageBox]::Show(
                        "Everything is installed but not running.`r`n`r`n" +
                        "Please start Everything, then check 'Use Everything (fast)' again.",
                        "Everything not running",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    ) | Out-Null
                }
                $chkEverything.Checked = $false
                return
            }

        } else {
            Set-EverythingInfo (Get-EverythingStatusText)
        }

        Update-SearchLayout
    } catch { }
})
# Si on sélectionne un tag trouvé : activer le filtre Tag + relancer la recherche

$comboFoundTags.Add_SelectedIndexChanged({

    try {

        if ($script:SuppressFoundTagsEvent) { return }

        $sel = $comboFoundTags.SelectedItem

        if ($null -ne $sel -and ($sel.ToString().Trim().Length -gt 0)) {

            if ($null -ne $chkTag) { $chkTag.Checked = $true }

            if ($null -ne $txtTag) {

                $val = $sel.ToString()

                # If the tag contains spaces, wrap it in quotes so the parser treats it as a single tag token.

                if ($val -match '\s') { $val = '"' + ($val -replace '"','""') + '"' }

                $txtTag.Text = $val

            }

            if (Get-Command Trigger-Search -ErrorAction SilentlyContinue) { Trigger-Search }

            elseif (Get-Command Run-SearchAndFillGrid -ErrorAction SilentlyContinue) { Run-SearchAndFillGrid }

        }

    } catch {}

})



$btnSearch = New-Object System.Windows.Forms.Button

$btnSearch.Text = "&Search (Ctrl+S)"

$btnSearch.UseMnemonic = $true
$btnSearch.Location = New-Object System.Drawing.Point(860, 48)

$btnSearch.Size = New-Object System.Drawing.Size(110, 26)

$btnSearch.Anchor = "Top,Right"

$gbSearch.Controls.Add($btnSearch)

# Rescan (F5): same criteria but forces directory scan cache refresh
$btnRescan = New-Object System.Windows.Forms.Button
$btnRescan.Text = "Rescan (F5)"
$btnRescan.Size = New-Object System.Drawing.Size(110, 24)
$btnRescan.Location = New-Object System.Drawing.Point(860, 24)
$btnRescan.Anchor = "Top,Right"
$btnRescan.Add_Click({
    try { Trigger-Search -ForceRefresh } catch { }
})
$gbSearch.Controls.Add($btnRescan)

# Search history (Ctrl+Y)
$btnHistory = New-Object System.Windows.Forms.Button
$btnHistory.Text = "History (Ctrl+Y)"
$btnHistory.Size = New-Object System.Drawing.Size(110, 24)
$btnHistory.Location = New-Object System.Drawing.Point(860, 78)
$btnHistory.Anchor = "Top,Right"
$btnHistory.Add_Click({
    try { Show-SearchHistoryDialog } catch { }
})
$gbSearch.Controls.Add($btnHistory)






# Make Enter trigger Search everywhere (incl. size/date fields)
try { $form.AcceptButton = $btnSearch } catch { }

$__enterTriggersSearch = {
    param($sender, $e)
    try {
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $e.SuppressKeyPress = $true
            Trigger-Search
        }
    } catch { }
}

if ($txtMinSize) { $txtMinSize.Add_KeyDown($__enterTriggersSearch) }
if ($txtMaxSize) { $txtMaxSize.Add_KeyDown($__enterTriggersSearch) }
if ($dtAfter)    { $dtAfter.Add_KeyDown($__enterTriggersSearch) }
if ($dtBefore)   { $dtBefore.Add_KeyDown($__enterTriggersSearch) }

# Pressing Enter in Directory triggers Search
$txtDir.Add_KeyDown({
    try {
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $_.SuppressKeyPress = $true
            $btnSearch.PerformClick()
        }
    } catch {}
})


$btnHelp = New-Object System.Windows.Forms.Button

$btnHelp.Text = "&Help (Ctrl+H)"

$btnHelp.UseMnemonic = $true
$btnHelp.Location = New-Object System.Drawing.Point(860, 78)

$btnHelp.Size = New-Object System.Drawing.Size(110, 26)

$btnHelp.Anchor = "Top,Right"

$gbSearch.Controls.Add($btnHelp)



# --- Layout (UI uniquement) : placement robuste pour éviter les chevauchements (DPI/resize)

function Layout-SearchControls {
    # Keeps the top search area usable on resize and avoids controls drifting to the far right.
    try {
        if (-not $gbSearch) { return }

        $padL = 10
        $padR = 10
        $gap  = 8

        $w = [int]$gbSearch.ClientSize.Width
        if ($w -le 0) { return }

        # Right-side button column
        $btnW = 110
        $btnH = 26
        $btnX = $w - $btnW - $padR
        if ($btnX -lt 0) { $btnX = 0 }

        foreach ($b in @($btnRescan, $btnSearch, $btnHistory, $btnHelp)) {
            if ($b) {
                $b.Width  = $btnW
                $b.Height = $btnH
                $b.Anchor = "Top,Right"
            }
        }

        if ($btnRescan)  { $btnRescan.Left  = $btnX; $btnRescan.Top  = 24 }
        if ($btnSearch)  { $btnSearch.Left  = $btnX; $btnSearch.Top  = 52 }
        if ($btnHistory) { $btnHistory.Left = $btnX; $btnHistory.Top = 80 }
        if ($btnHelp)    { $btnHelp.Left    = $btnX; $btnHelp.Top    = 108 }

        # Everything else must fit before the button column
        $fieldsRight = $btnX - $gap
        if ($fieldsRight -lt 200) { $fieldsRight = $w - $padR }

        # Row Y
        $yDir  = 18
        $yBody = 46
        $yTag  = 74

        # ---- Directory
        if ($lblDir) { $lblDir.Left = $padL; $lblDir.Top = 22 }

        $dirX = 80
        try { if ($lblDir) { $dirX = $lblDir.Left + $lblDir.Width + 8 } } catch { }

        if ($btnBrowse) {
            $btnBrowse.Width  = 110
            $btnBrowse.Height = 24
            $btnBrowse.Top    = $yDir
            $btnBrowse.Anchor = "Top,Right"
            $btnBrowse.Left   = [Math]::Max($dirX + 120, $fieldsRight - $btnBrowse.Width)
        }

        if ($txtDir) {
            $txtDir.Top    = $yDir
            $txtDir.Left   = $dirX
            $txtDir.Anchor = "Top,Left,Right"
            $txtDir.Width  = [Math]::Max(120, ($btnBrowse.Left - $gap) - $dirX)
        }

        # ---- Left column: Body / Tag
        if ($chkBody) { $chkBody.Left = $padL; $chkBody.Top = $yBody + 4 }
        if ($chkTag)  { $chkTag.Left  = $padL; $chkTag.Top  = $yTag + 4 }

        $leftX = $dirX
        try {
            if ($chkBody) { $leftX = $chkBody.Left + $chkBody.Width + 6 }
        } catch { }

        # Right column anchor point (types/tags found)
        $rightColX = 520
        try {
            if ($btnResetBody -and $txtBody) {
                $rightColX = [Math]::Max($rightColX, ($txtBody.Left + 260 + $btnResetBody.Width + 30))
            }
        } catch { }
        $maxRightColX = $fieldsRight - 220
        if ($maxRightColX -lt 300) { $maxRightColX = 300 }
        if ($rightColX -gt $maxRightColX) { $rightColX = $maxRightColX }
        if ($rightColX -lt ($leftX + 250)) { $rightColX = $leftX + 250 }

        $leftColRight = $rightColX - $gap

        # Body textbox + reset
        if ($txtBody) {
            $txtBody.Left   = $leftX
            $txtBody.Top    = $yBody
            $txtBody.Anchor = "Top,Left"
            $txtBody.Width  = [Math]::Max(120, ($leftColRight - $gap - 26) - $txtBody.Left)
        }
        if ($btnResetBody) {
            $btnResetBody.Width  = 26
            $btnResetBody.Height = 24
            $btnResetBody.Top    = $yBody
            $btnResetBody.Anchor = "Top,Left"
            if ($txtBody) { $btnResetBody.Left = $txtBody.Left + $txtBody.Width + 6 }
        }

        # Tag textbox + reset
        if ($txtTag) {
            $txtTag.Left   = $leftX
            $txtTag.Top    = $yTag
            $txtTag.Anchor = "Top,Left"
            $txtTag.Width  = [Math]::Max(120, ($leftColRight - $gap - 26) - $txtTag.Left)
        }
        if ($btnResetTag) {
            $btnResetTag.Width  = 26
            $btnResetTag.Height = 24
            $btnResetTag.Top    = $yTag
            $btnResetTag.Anchor = "Top,Left"
            if ($txtTag) { $btnResetTag.Left = $txtTag.Left + $txtTag.Width + 6 }
        }

        # ---- Right column: File types / Tags found
        if ($lblTypes) { $lblTypes.Left = $rightColX; $lblTypes.Top = $yBody + 4 }
        if ($comboTypes) {
            $comboTypes.Left   = $rightColX + 70
            $comboTypes.Top    = $yBody
            $comboTypes.Anchor = "Top,Left,Right"
            $comboTypes.Width  = [Math]::Max(120, $fieldsRight - $comboTypes.Left)
        }

        if ($lblFoundTags) { $lblFoundTags.Left = $rightColX; $lblFoundTags.Top = $yTag + 4 }
        if ($comboFoundTags) {
            $comboFoundTags.Left   = $rightColX + 70
            $comboFoundTags.Top    = $yTag
            $comboFoundTags.Anchor = "Top,Left,Right"
            $comboFoundTags.Width  = [Math]::Max(220, $fieldsRight - $comboFoundTags.Left)
        }

    } catch { }
}




$gbSearch.Add_Resize({ Layout-SearchControls })



Layout-SearchControls



# --- Results : uniquement la grid, sans label "Files found"



$grid = New-Object System.Windows.Forms.DataGridView

$grid.Dock = "Fill"

$grid.ReadOnly = $true

$grid.AllowUserToAddRows    = $false

$grid.AllowUserToDeleteRows = $false

$grid.SelectionMode         = "FullRowSelect"

$grid.MultiSelect           = $true

$grid.RowHeadersVisible     = $false

$grid.AutoGenerateColumns   = $false

$grid.AllowUserToOrderColumns = $true

$grid.AllowUserToResizeRows   = $false

$grid.ColumnHeadersVisible    = $true

$grid.ScrollBars              = "Both"

$gbResults.Controls.Add($grid)




function Lock-GridRowSizing {
    # Enforce "no row-height resizing" (both user and autosize paths)
    try {
        if ($null -ne $grid) {
            $grid.AllowUserToResizeRows = $false
            $grid.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::None
            try { $grid.RowTemplate.Resizable = [System.Windows.Forms.DataGridViewTriState]::False } catch {}
            try { $grid.RowHeadersWidthSizeMode = [System.Windows.Forms.DataGridViewRowHeadersWidthSizeMode]::DisableResizing } catch {}
        }
    } catch { }
}

# Lock row sizing once right after grid creation
Lock-GridRowSizing

# Colonnes

$colPath = New-Object System.Windows.Forms.DataGridViewTextBoxColumn

$colPath.Name = "Path"

$colPath.HeaderText = "Path"

$colPath.DataPropertyName = "Path"

$colPath.MinimumWidth = 200

$colPath.AutoSizeMode = "None"

$colPath.SortMode = "Programmatic"

[void]$grid.Columns.Add($colPath)





$colFileType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn

$colFileType.Name = "FileType"

$colFileType.HeaderText = "File type"

$colFileType.DataPropertyName = "FileType"

$colFileType.MinimumWidth = 140

$colFileType.AutoSizeMode = "None"

$colFileType.SortMode = "Programmatic"

[void]$grid.Columns.Add($colFileType)



$colSize = New-Object System.Windows.Forms.DataGridViewTextBoxColumn

$colSize.Name = "SizeBytes"

$colSize.HeaderText = "Size"

$colSize.DataPropertyName = "Size"

$colSize.MinimumWidth = 80

$colSize.AutoSizeMode = "None"

$colSize.SortMode = "Programmatic"

$colSize.DefaultCellStyle.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleRight

[void]$grid.Columns.Add($colSize)



$colLastMod = New-Object System.Windows.Forms.DataGridViewTextBoxColumn

$colLastMod.Name = "LastModified"

$colLastMod.HeaderText = "Last modified"

$colLastMod.DataPropertyName = "LastModified"

$colLastMod.MinimumWidth = 140

$colLastMod.AutoSizeMode = "None"

$colLastMod.SortMode = "Programmatic"

[void]$grid.Columns.Add($colLastMod)





$colCreated = New-Object System.Windows.Forms.DataGridViewTextBoxColumn

$colCreated.Name = "Created"

$colCreated.HeaderText = "Created"

$colCreated.DataPropertyName = "Created"

$colCreated.MinimumWidth = 120

$colCreated.AutoSizeMode = "None"

$colCreated.SortMode = "Programmatic"

[void]$grid.Columns.Add($colCreated)



$colBody = New-Object System.Windows.Forms.DataGridViewTextBoxColumn

$colBody.Name = "Body"

$colBody.HeaderText = "Body"

$colBody.DataPropertyName = "Body"

$colBody.MinimumWidth = 120

$colBody.AutoSizeMode = "None"

$colBody.SortMode = "Programmatic"

[void]$grid.Columns.Add($colBody)



$colTags = New-Object System.Windows.Forms.DataGridViewTextBoxColumn

$colTags.Name = "Tags"

$colTags.HeaderText = "Tags"

$colTags.DataPropertyName = "Tags"

$colTags.MinimumWidth = 120

$colTags.AutoSizeMode = "None"

$colTags.SortMode = "Programmatic"

[void]$grid.Columns.Add($colTags)



$colTagCount = New-Object System.Windows.Forms.DataGridViewTextBoxColumn

$colTagCount.Name = "TagCount"

$colTagCount.HeaderText = "Tag count"

$colTagCount.DataPropertyName = "TagCount"

$colTagCount.MinimumWidth = 70

$colTagCount.AutoSizeMode = "None"

$colTagCount.SortMode = "Programmatic"

$colTagCount.DefaultCellStyle.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleCenter

[void]$grid.Columns.Add($colTagCount)



# Row meta

function Save-RowMeta($row, $obj) { $row.Tag = $obj }

function Get-RowMeta($row) { return $row.Tag }



# ------------------------------ Actions area ------------------------------



function Make-ActionButton([string]$text, [int]$x, [int]$y) {

    $b = New-Object System.Windows.Forms.Button

    $b.Text = $text

    $b.Location = New-Object System.Drawing.Point($x, $y)

    $b.Size = New-Object System.Drawing.Size(130, 28)

    return $b

}





# Buttons order matches context menu order

$btnExecute     = Make-ActionButton "&Execute (Ctrl+E)"          10  28

$btnOpenFolder  = Make-ActionButton "Open &folder (Ctrl+F)"      150 28

$btnDescribe    = Make-ActionButton "&Description (Ctrl+D)"      290 28

$btnMove        = Make-ActionButton "&Move file(s)... (Ctrl+M)"       430 28

$btnDelete      = Make-ActionButton "De&lete file(s) (Ctrl+L)"      570 28

$btnCopyPath    = Make-ActionButton "&Copy path (Ctrl+C)"        710 28



$btnBodyRename  = Make-ActionButton "&Body rename (Ctrl+B)"      10  60

$btnAdd         = Make-ActionButton "&Add tags (Ctrl+A)"         150 60

$btnRemove      = Make-ActionButton "&Remove tags (Ctrl+R)"      290 60

$btnCopyTags    = Make-ActionButton "Copy &tags (Ctrl+T)"        430 60

$btnDup         = Make-ActionButton "Show d&uplicates (Ctrl+U)"       570 60

# Optional: confirm duplicates by hash (accurate but slower; only hashes within candidate groups)
$chkDupHash = New-Object System.Windows.Forms.CheckBox
$chkDupHash.Text = "Hash duplicates"
$chkDupHash.AutoSize = $true
$chkDupHash.Location = New-Object System.Drawing.Point(710, 64)
$chkDupHash.Anchor = "Top,Left"
$chkDupHash.Checked = [bool]$script:DupUseHash
$chkDupHash.Add_CheckedChanged({
    try {
        # Cancel any running duplicate computation (hashing) before recomputing.
        try { Cancel-DuplicateWorker } catch { }

        $script:DupUseHash = [bool]$chkDupHash.Checked
        if ($script:DupModeEnabled) { Do-FindDuplicates }
    } catch { }
})
$gbActions.Controls.Add($chkDupHash)




foreach ($b in @($btnExecute,$btnOpenFolder,$btnDescribe,$btnMove,$btnDelete,$btnCopyPath,$btnBodyRename,$btnAdd,$btnRemove,$btnCopyTags,$btnDup)) {

    $b.Anchor = "Top,Left"

    $gbActions.Controls.Add($b)

}







# ------------------------------ Context menu ------------------------------



$ctx = New-Object System.Windows.Forms.ContextMenuStrip



function Add-CtxItem([string]$text, [scriptblock]$handler, [bool]$bold=$false) {

    $mi = New-Object System.Windows.Forms.ToolStripMenuItem

    $mi.Text = $text
    $mi.ShowShortcutKeys = $true
if ($bold) {

        $mi.Font = New-Object System.Drawing.Font($mi.Font, [System.Drawing.FontStyle]::Bold)

    }

    $mi.Add_Click($handler)

    [void]$ctx.Items.Add($mi)

}



$ctx.Add_Opening({ Enable-KeyboardCues $ctx })

# L'ordre demandé

Add-CtxItem "Execute file (Ctrl+E)"       { $btnExecute.PerformClick() } $true

Add-CtxItem "Open &folder (Ctrl+F)"        { $btnOpenFolder.PerformClick() } $false

Add-CtxItem "&Description (Ctrl+D)"        { $btnDescribe.PerformClick() } $false


Add-CtxItem "&Move file(s)... (Ctrl+M)"     { $btnMove.PerformClick() } $false
Add-CtxItem "De&lete file(s) (Ctrl+L)"        { $btnDelete.PerformClick() } $false

Add-CtxItem "&Copy path (Ctrl+C)"          { $btnCopyPath.PerformClick() } $false

Add-CtxItem "&Body rename (Ctrl+B)"        { $btnBodyRename.PerformClick() } $false

[void]$ctx.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))



Add-CtxItem "&Add tags (Ctrl+A)"     { $btnAdd.PerformClick() } $false

Add-CtxItem "&Remove tags (Ctrl+R)"  { $btnRemove.PerformClick() } $false

Add-CtxItem "Copy &tags (Ctrl+T)"    { $btnCopyTags.PerformClick() } $false



[void]$ctx.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$script:CtxDupItem = New-Object System.Windows.Forms.ToolStripMenuItem
$script:CtxDupItem.Text = "Show d&uplicates (Ctrl+U)"
$script:CtxDupItem.ShowShortcutKeys = $true
$script:CtxDupItem.Add_Click({ $btnDup.PerformClick() })
[void]$ctx.Items.Add($script:CtxDupItem)

[void]$ctx.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

Add-CtxItem "&Help (Ctrl+H)" { $btnHelp.PerformClick() } $false



$grid.ContextMenuStrip = $ctx
$grid.add_Sorted({ if ($script:DupModeEnabled) { Apply-DuplicatesToGrid } })







# Right-click should select row under cursor (so context menu actions apply to that row)

$grid.Add_MouseDown({

        param($sender, $e)



        Debug-Log ("Grid MouseDown: Button={0} X={1} Y={2}" -f $e.Button, $e.X, $e.Y)

    try {

        if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {

            $hit = $grid.HitTest($e.X, $e.Y)

            if ($hit -and $hit.RowIndex -ge 0 -and $hit.RowIndex -lt $grid.Rows.Count) {

                if (-not $grid.Rows[$hit.RowIndex].Selected) {

                    $grid.ClearSelection()

                    $grid.Rows[$hit.RowIndex].Selected = $true

                    $grid.CurrentCell = $grid.Rows[$hit.RowIndex].Cells[0]

                }

            }

        }

    } catch {}

})

# ------------------------------ Fit grid columns ------------------------------



function Fit-GridColumns {

    try {

        $client = [int]$grid.ClientSize.Width

        if ($client -le 0) { return }



        foreach ($name in @("Created","Body","Tags","TagCount")) {

            $c = $grid.Columns[$name]

            if ($null -eq $c) { continue }

            $grid.AutoResizeColumn($c.Index, [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::DisplayedCells)



            if ($name -eq "Created"  -and $c.Width -gt 200) { $c.Width = 200 }

            if ($name -eq "TagCount" -and $c.Width -gt 120) { $c.Width = 120 }

            if (($name -eq "Body" -or $name -eq "Tags") -and $c.Width -gt 360) { $c.Width = 360 }

            if ($c.Width -lt $c.MinimumWidth) { $c.Width = $c.MinimumWidth }

        }



        $pathCol = $grid.Columns["Path"]

        if ($null -eq $pathCol) { return }



        $total = 0

        foreach ($c in $grid.Columns) {

            if ($c.Visible) { $total += [int]$c.Width }

        }

        $delta = $client - $total

        if ($delta -ne 0) {

            $pathCol.Width = [Math]::Max($pathCol.MinimumWidth, [int]$pathCol.Width + $delta)

        }

    } catch {}

}



# ------------------------------ Selection helpers ------------------------------



function Get-SelectedPaths {

    $paths = @()

    foreach ($r in $grid.SelectedRows) {

        try {

            $m = Get-RowMeta $r

            if ($null -ne $m -and $m.Path) { $paths += [string]$m.Path }

        } catch {}

    }

    return $paths

}



function Ensure-OneOrMoreSelected { return ((Get-Count $grid.SelectedRows) -gt 0) }

function Ensure-ExactlyOneSelected { return ((Get-Count $grid.SelectedRows) -eq 1) }



function Get-FirstSelectedIndex {

    if ((Get-Count $grid.SelectedRows) -gt 0) {

        return [int]$grid.SelectedRows[0].Index

    }

    return -1

}



# ------------------------------ Rename safe ------------------------------



function Rename-FileSafe([string]$OldPath, [string]$NewPath) {

    if ($OldPath -eq $NewPath) { return "skipped" }

    if (Test-Path -LiteralPath $NewPath) { throw "Target exists: $NewPath" }

    Rename-Item -LiteralPath $OldPath -NewName ([System.IO.Path]::GetFileName($NewPath)) -ErrorAction Stop

    return "changed"

}



# ------------------------------ Union tags from files ------------------------------



function Get-UnionTagsFromFiles([string[]]$Paths) {

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($p in $Paths) {

        if (-not (Test-Path -LiteralPath $p)) { continue }

        try {

            $it = Get-Item -LiteralPath $p -ErrorAction Stop

            $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($it.Name)

            $tags = Normalize-Tags (Get-TagsFromNameNoExt $nameNoExt)

            foreach ($t in $tags) { [void]$set.Add($t) }

        } catch {}

    }

    return @($set | Sort-Object)

}



# ------------------------------ Remove tags dialog ------------------------------



function Show-RemoveTagsDialog([System.Windows.Forms.IWin32Window]$Owner, [string[]]$AvailableTags) {

    $dlg = New-Object System.Windows.Forms.Form

    $dlg.Text = "Remove tags"

    $dlg.StartPosition = "CenterParent"

    $dlg.Size = New-Object System.Drawing.Size(420, 420)

    $dlg.MinimizeBox = $false

    $dlg.MaximizeBox = $false

    $dlg.FormBorderStyle = 'FixedDialog'



    $chkAll = New-Object System.Windows.Forms.CheckBox

    $chkAll.Text = "Remove all (*)"

    $chkAll.AutoSize = $true

    $chkAll.Location = New-Object System.Drawing.Point(12, 12)

    $dlg.Controls.Add($chkAll)



    $lb = New-Object System.Windows.Forms.CheckedListBox

    $lb.Location = New-Object System.Drawing.Point(12, 40)

    $lb.Size = New-Object System.Drawing.Size(380, 280)

    $lb.CheckOnClick = $true

    foreach ($t in $AvailableTags) { [void]$lb.Items.Add($t, $false) }

    $dlg.Controls.Add($lb)



    $ok = New-Object System.Windows.Forms.Button

    $ok.Text = "OK"

    $ok.Location = New-Object System.Drawing.Point(232, 330)

    $ok.Size = New-Object System.Drawing.Size(75, 28)

    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $dlg.Controls.Add($ok)



    $cancel = New-Object System.Windows.Forms.Button

    $cancel.Text = "Cancel"

    $cancel.Location = New-Object System.Drawing.Point(317, 330)

    $cancel.Size = New-Object System.Drawing.Size(75, 28)

    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $dlg.Controls.Add($cancel)



    $dlg.AcceptButton = $ok

    $dlg.CancelButton = $cancel



    $chkAll.Add_CheckedChanged({

        $lb.Enabled = -not $chkAll.Checked

    })



    $res = $dlg.ShowDialog($Owner)

    if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return $null }



    $picked = @()

    if (-not $chkAll.Checked) {

        foreach ($it in $lb.CheckedItems) { $picked += [string]$it }

    }



    return [PSCustomObject]@{

        RemoveAll = [bool]$chkAll.Checked

        Tags      = $picked

    }

}



# ------------------------------ Search + grid fill ------------------------------



$script:CurrentItems    = @()

$script:LastSearchItems = @()  # last full search result list (pre-duplicates)

$script:SortColumnName  = $null

$script:SortAscending   = $true



function Add-RowFromObj($obj) {

    # Faster bulk add: pass values in column order (matches grid column definitions)
    $idx = $grid.Rows.Add(
        $obj.Path,
        $obj.FileType,
        $obj.Size,
        $obj.LastModified,
        $obj.Created,
        $obj.Body,
        $obj.Tags,
        $obj.TagCount
    )

    $row = $grid.Rows[$idx]
    Save-RowMeta $row $obj
}

function Restore-SelectionAfterRefresh([string[]]$PreferredPaths, [int]$FallbackIndex, [string]$CurrentPath) {

    if ($script:PendingSelectionPaths -and (Get-Count $script:PendingSelectionPaths) -gt 0) {
        $PreferredPaths = @($PreferredPaths) + @($script:PendingSelectionPaths)
        $script:PendingSelectionPaths = $null
        $script:PendingSelectionCurrentPath = $null
    }

    $pref = @(Force-Array $PreferredPaths)

    $pickedRows = @()



    if ((Get-Count $pref) -gt 0) {

        foreach ($r in $grid.Rows) {

            $m = Get-RowMeta $r

            if ($null -ne $m -and $pref -contains [string]$m.Path) { $pickedRows += $r }

        }

    }



    $grid.ClearSelection()

    if ((Get-Count $pickedRows) -gt 0) {

        foreach ($r in $pickedRows) { $r.Selected = $true }

        try {

            $targetRow = $null
        if ($CurrentPath) {
            foreach ($rr in $pickedRows) {
                try {
                    $p = $null
                    try { $p = $rr.Cells["Path"].Value } catch { }
                    if (-not $p) { try { $p = $rr.Cells["FullPath"].Value } catch { } }
                    if ($p -and ($p.ToString() -ieq $CurrentPath.ToString())) { $targetRow = $rr; break }
                } catch { }
            }
        }
        if (-not $targetRow) { $targetRow = $pickedRows[0] }
        try { $grid.CurrentCell = $targetRow.Cells["Path"] } catch { try { $grid.CurrentCell = $targetRow.Cells[0] } catch { } }

            $grid.FirstDisplayedScrollingRowIndex = [int]$pickedRows[0].Index

        } catch {}

        return

    }



    if ($grid.Rows.Count -gt 0) {

        $i = [Math]::Min([Math]::Max(0, $FallbackIndex), $grid.Rows.Count - 1)

        $grid.Rows[$i].Selected = $true

        try {

            $grid.CurrentCell = $grid.Rows[$i].Cells["Path"]

            $grid.FirstDisplayedScrollingRowIndex = $i

        } catch {}

    }

}
function Get-SelectedPathsFromGrid {
    $paths = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($r in @($grid.SelectedRows)) {
            try {
                $p = [string]$r.Cells["Path"].Value
                if (-not [string]::IsNullOrWhiteSpace($p)) { $paths.Add($p) }
            } catch {}
        }
    } catch {}
    return ,($paths.ToArray())
}

function Apply-DuplicatesToGrid {

    if (-not $script:DupModeEnabled) { return }

    if (-not $script:DupGroupByPath -or $script:DupGroupMap.Count -eq 0) {
        foreach ($r in @($grid.Rows)) {
            try {
                $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty
                $r.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Empty
                $r.Visible = $true
            } catch {}
        }
        return
    }

    foreach ($r in @($grid.Rows)) {

        $p = ""
        try { $p = [string]$r.Cells["Path"].Value } catch {}

        $gid = $null
        if ($p -and $script:DupGroupMap.ContainsKey($p)) { $gid = $script:DupGroupMap[$p] }

        if ($gid) {
            try {
                $r.DefaultCellStyle.BackColor = $script:DupColorByGroup[$gid]
                $r.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
                $r.Visible = $true
            } catch {}
        } else {
            try {
                $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty
                $r.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Empty
                if ($script:DupHideNonDup) { $r.Visible = $false } else { $r.Visible = $true }
            } catch {}
        }
    }
}




function Fill-GridFromItems($items, [string[]]$PreferredPaths, [int]$FallbackIndex, [switch]$NoFitColumns = $true) {

    $h0 = 0

    try { $h0 = [int]$grid.HorizontalScrollingOffset } catch { $h0 = 0 }



    $grid.SuspendLayout()

    try {

        $grid.Rows.Clear()

        foreach ($obj in $items) { Add-RowFromObj $obj }

    } finally {

        $grid.ResumeLayout()

    }



    if (-not $NoFitColumns) { Fit-GridColumns }

    Restore-SelectionAfterRefresh -PreferredPaths $PreferredPaths -FallbackIndex $FallbackIndex



    # on ne bouge pas le scroll horizontal automatiquement

    try { $grid.HorizontalScrollingOffset = $h0 } catch {}


    if ($script:DupModeEnabled -and (-not $script:ApplyingDupMode)) {
        $script:ApplyingDupMode = $true
        try {
            Apply-DuplicatesToGrid
        } finally {
            $script:ApplyingDupMode = $false
        }
    }


    # Keep row-height resizing disabled even after refills
    Lock-GridRowSizing

}





# ------------------------------ Async search (avoid UI freeze) ------------------------------



$script:PendingSearchArgs = $null



if ($null -eq $script:SearchWorker) {

    $script:SearchWorker = New-Object System.ComponentModel.BackgroundWorker

    $script:SearchWorker.WorkerSupportsCancellation = $true



    $script:SearchWorker.add_DoWork({

        param($sender, $e)

        $a = $e.Argument



        $prevRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace

        [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace = $script:MainRunspace





        Debug-Log ("Worker DoWork: entered (ThreadId={0})" -f [System.Threading.Thread]::CurrentThread.ManagedThreadId)

        try {

            Debug-Log "Worker: calling Search-Files"

            $items = @(Search-Files -Dir $a.Dir -UseBody $a.UseBody -BodyFilter $a.BodyFilter -UseTag $a.UseTag -TagFilter $a.TagFilter -AllowedExts $a.Allowed -CancelCheck { $sender.CancellationPending })

            Debug-Log ("Worker: Search-Files returned {0} items" -f (Get-Count $items))

            if ($sender.CancellationPending) {
                Debug-Log "Worker: cancellation pending -> cancelling"
                $e.Cancel = $true
                return
            }

            $e.Result = [PSCustomObject]@{

                Ok           = $true

                Items        = $items

                Preferred    = $a.Preferred

                Fallback     = $a.Fallback

                Allowed      = $a.Allowed

                Dir          = $a.Dir

            }

        } catch {

            $e.Result = [PSCustomObject]@{

                Ok      = $false

                Error   = $_.Exception.Message

                Preferred = $a.Preferred

                Fallback  = $a.Fallback

                Allowed   = $a.Allowed

                Dir       = $a.Dir

            }

        }

        finally {

            [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace = $prevRunspace

        }

    })



    $script:SearchWorker.add_RunWorkerCompleted({

        param($sender, $e)



        try {

            # réactive l'UI

            try { $btnSearch.Enabled = $true } catch {}

            try { $btnBrowse.Enabled = $true } catch {}

            try { $btnHelp.Enabled   = $true } catch {}

            try { $comboTypes.Enabled = $true } catch {}

        } catch {}

        $script:IsSearching = $false

        if ($e.Cancelled -or $script:LastSearchInterrupted) {

            Set-Status "Search interrupted"
            try { Set-Info "Interrupted" } catch { }
            $script:LastSearchInterrupted = $false
            $script:PendingSearchArgs = $null
            $script:PendingSearchRequest = $false
            return

        } else {

            $r = $e.Result

            if ($null -ne $r -and $r.Ok) {

                $script:CurrentItems = @($r.Items)

                Fill-GridFromItems -items $script:CurrentItems -PreferredPaths $r.Preferred -FallbackIndex $r.Fallback

                try { Refresh-TagsFound } catch {}

                if ($script:DupModeEnabled -and -not $script:DupApplying) { Do-FindDuplicates }
                Debug-Log ("UI: filling grid with {0} items" -f (Get-Count $script:CurrentItems))

                Update-FoundCountStatus -UpdatingView:$UpdatingView

            } elseif ($null -ne $r -and -not $r.Ok) {

                [System.Windows.Forms.MessageBox]::Show($form, "Search error:`r`n$($r.Error)", "Search",

                    [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null

            }

        }

        try { Set-Info "Ready" } catch { }





        # si une recherche a été demandée pendant l'exécution, on la lance maintenant

        if ($null -ne $script:PendingSearchArgs) {

            $next = $script:PendingSearchArgs

            $script:PendingSearchArgs = $null

            Start-SearchSync -PreferredPaths $next.Preferred -FallbackIndex $next.Fallback

        }

    })

}




function Request-InterruptSearch {
    # Called when user presses Esc during an active search (synchronous search).
    if (-not $script:IsSearching) { return }

    # Mark as explicitly interrupted by the user
    $script:LastSearchInterrupted = $true

    # Signal cancellation to the synchronous loop (Search-Files reads this via -CancelCheck)
    $script:CancelSearchRequested = $true

    # Do not auto-run pending searches after an explicit interruption
    $script:PendingSearchArgs    = $null
    $script:PendingSearchRequest = $false

    # Update UI immediately
    try { Set-Info "Interrupted" } catch { }
    try { Set-Status "Search interrupted" } catch { }
    try { [System.Windows.Forms.Application]::DoEvents() } catch { }
}



function Start-SearchAsync([string[]]$PreferredPaths, [int]$FallbackIndex) {

    # If we're restoring settings and no explicit selection preference was provided,
    # use the pending selection loaded from settings so the initial grid refresh can restore selection.
    if ((-not $PreferredPaths -or $PreferredPaths.Count -eq 0) -and $script:PendingSelectionPaths -and $script:PendingSelectionPaths.Count -gt 0) {
        $PreferredPaths = @($script:PendingSelectionPaths)
    }

    $dir = [string]$txtDir.Text

    if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path -LiteralPath $dir)) {
        try { $grid.Rows.Clear() } catch {}
        $script:CurrentItems = @()
        Set-Status ""
        Set-Info "Ready"
        return
    }

    $searchArgs = [PSCustomObject]@{
        Dir          = $dir
        UseBody      = [bool]$chkBody.Checked
        UseTag       = [bool]$chkTag.Checked
        BodyFilter   = [string]$txtBody.Text
        TagFilter    = [string]$txtTag.Text
        Allowed      = Get-AllowedExtsFromChoice (Get-SelectedTypeLabel $comboTypes)
        Preferred    = $PreferredPaths
        Fallback     = $FallbackIndex
        UpdatingView = [bool]$UpdatingView

        # Advanced filters
        NoSubdirs     = [bool]($chkNoSubdirs.Checked)
        MinSizeText   = [string]$txtMinSize.Text
        MaxSizeText   = [string]$txtMaxSize.Text
        AfterOn       = [bool]($dtAfter.Checked)
        AfterDate     = [datetime]$dtAfter.Value
        BeforeOn      = [bool]($dtBefore.Checked)
        BeforeDate    = [datetime]$dtBefore.Value

        UseEverything = [bool]($chkEverything.Checked)
        ForceRefresh = [bool]$ForceRefresh
    }


    # Defer during initialization / restore
    if ($script:IsRestoring -or $script:IsInitializing) {
        Debug-Log "Start-SearchAsync: init/restore in progress -> pending"
        $script:PendingSearchRequest = $true
        $script:PendingSearchArgs = $searchArgs
        return
    }

    # If already searching, just queue latest args
    if ($script:IsSearching -or ($null -ne $script:SearchWorker -and $script:SearchWorker.IsBusy)) {
        Debug-Log "Start-SearchAsync: already searching -> pending"
        $script:PendingSearchRequest = $true
        $script:PendingSearchArgs = $searchArgs
        return
    }

    # New run
    $script:IsSearching = $true
    $script:LastSearchInterrupted = $false
    $script:PendingSearchRequest = $false

    # Disable UI while worker runs
    try {
        try { $btnSearch.Enabled = $false } catch {}
        try { $btnBrowse.Enabled = $false } catch {}
        try { $btnHelp.Enabled   = $false } catch {}
        try { $comboTypes.Enabled = $false } catch {}
    } catch {}

    # Activity indicator (blinking)
    Start-Progress "Searching..." -Marquee
Debug-Log ("Start-SearchAsync: Dir='{0}'" -f $searchArgs.Dir)
    Debug-Log ("  BodyEnabled={0} TagEnabled={1} Type='{2}'" -f $searchArgs.UseBody, $searchArgs.UseTag, [string]$comboTypes.SelectedItem)

    # Launch background worker (no UI freeze => blinking works)
    try {
        $script:SearchWorker.RunWorkerAsync($searchArgs)
    } catch {
        Debug-Log ("Start-SearchAsync: ERROR {0}" -f $_.Exception.Message)
        $script:IsSearching = $false
        Set-Info "Ready"
    }
}





function Start-SearchSync([string[]]$PreferredPaths, [int]$FallbackIndex, [switch]$UpdatingView, [switch]$ForceRefresh) {


    # If a duplicate-hash computation is running, cancel it before starting a new search.
    try { Cancel-DuplicateWorker } catch { }

    # If we're restoring settings and no explicit selection preference was provided,
    # use the pending selection loaded from settings so the initial grid refresh can restore selection.
    if ((-not $PreferredPaths -or $PreferredPaths.Count -eq 0) -and $script:PendingSelectionPaths -and $script:PendingSelectionPaths.Count -gt 0) {
        $PreferredPaths = @($script:PendingSelectionPaths)
    }

    $dir = [string]$txtDir.Text

    Add-RecentDir $dir
        $script:LastDirText = $dir
        if ($txtDir -and ($txtDir.Text -ne $dir)) { $txtDir.Text = $dir; $txtDir.SelectionStart = $($txtDir.Text.Length); $txtDir.SelectionLength = 0 }

    if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path -LiteralPath $dir)) {
        try { $grid.Rows.Clear() } catch {}
        $script:CurrentItems = @()
        Set-Status ""
        Set-Info "Ready"
        return
    }

    $searchArgs = [PSCustomObject]@{
        Dir          = $dir
        UseBody      = [bool]$chkBody.Checked
        UseTag       = [bool]$chkTag.Checked
        BodyFilter   = [string]$txtBody.Text
        TagFilter    = [string]$txtTag.Text
        Allowed      = Get-AllowedExtsFromChoice (Get-SelectedTypeLabel $comboTypes)
        Preferred    = $PreferredPaths
        Fallback     = $FallbackIndex
        UpdatingView = [bool]$UpdatingView

        # Advanced filters
        NoSubdirs     = [bool]($chkNoSubdirs.Checked)
        MinSizeText   = [string]$txtMinSize.Text
        MaxSizeText   = [string]$txtMaxSize.Text
        AfterOn       = [bool]($dtAfter.Checked)
        AfterDate     = [datetime]$dtAfter.Value
        BeforeOn      = [bool]($dtBefore.Checked)
        BeforeDate    = [datetime]$dtBefore.Value

        UseEverything = [bool]($chkEverything.Checked)
    }

    
    # Record into search history (only when user actually launches a search)
    try { Add-SearchHistoryFromArgs $searchArgs } catch { }

# Defer during initialization / restore
    if ($script:IsRestoring -or $script:IsInitializing) {
        Debug-Log "Start-SearchSync: init/restore in progress -> pending"
        $script:PendingSearchRequest = $true
        $script:PendingSearchArgs = $searchArgs
        return
    }

    # If already searching, just queue latest args
    if ($script:IsSearching) {
        Debug-Log "Start-SearchSync: already searching -> pending"
        $script:PendingSearchRequest = $true
        $script:PendingSearchArgs = $searchArgs
        return
    }

    # New run (synchronous)
    # Normal searches replace any prior operation summary in the left status.
    if (-not $UpdatingView) { try { $script:LastOpStatusLeft = "" } catch { } }

    $script:IsSearching = $true
    $script:LastSearchInterrupted = $false
    $script:CancelSearchRequested = $false
    $script:PendingSearchRequest  = $false
    $script:PendingSearchArgs     = $null

    # Disable UI while searching
    try {
        try { $btnSearch.Enabled = $false } catch {}
        try { $btnBrowse.Enabled = $false } catch {}
        try { $btnHelp.Enabled   = $false } catch {}
        try { $comboTypes.Enabled = $false } catch {}
    } catch {}
    # Activity indicator (no blinking in synchronous mode)
    if ($UpdatingView) {
        Set-Info "Updating view"
    } else {
        Start-Progress "Searching..." -Marquee
}
    try { [System.Windows.Forms.Application]::DoEvents() } catch { }

    Debug-Log ("Start-SearchSync: Dir='{0}'" -f $searchArgs.Dir)
    Debug-Log ("  BodyEnabled={0} TagEnabled={1} Type='{2}'" -f $searchArgs.UseBody, $searchArgs.UseTag, [string]$comboTypes.SelectedItem)

    try {

        $cancel = {
            try { [System.Windows.Forms.Application]::DoEvents() } catch { }
            return [bool]$script:CancelSearchRequested
        }
        # Discrete Everything indicator (UI only for now)
        if ($searchArgs.UseEverything) {
            Set-EverythingInfo (Get-EverythingStatusText)
        } else {
            Set-EverythingInfo "Everything: off"
        }

        $minBytes = Parse-SizeToBytes $searchArgs.MinSizeText
        $maxBytes = Parse-SizeToBytes $searchArgs.MaxSizeText

        $after = $null
        $before = $null

        if ($searchArgs.AfterOn) {
            try { $after = $searchArgs.AfterDate.Date } catch { $after = $null }
        }
        if ($searchArgs.BeforeOn) {
            try { $before = $searchArgs.BeforeDate.Date.AddDays(1).AddTicks(-1) } catch { $before = $null }
        }

                    $items = Search-Files -Dir $searchArgs.Dir -UseBody $searchArgs.UseBody -BodyFilter $searchArgs.BodyFilter -UseTag $searchArgs.UseTag -TagFilter $searchArgs.TagFilter -AllowedExts $searchArgs.Allowed -NoSubdirs $searchArgs.NoSubdirs -MinSizeBytes $minBytes -MaxSizeBytes $maxBytes -ModifiedAfter $after -ModifiedBefore $before -CancelCheck $cancel -ForceRefresh:$ForceRefresh
if ($script:CancelSearchRequested -or $script:LastSearchInterrupted) {
            Set-Status "Search interrupted"
            Set-Info "Interrupted"
            $script:CancelSearchRequested = $false
            $script:LastSearchInterrupted = $false
            $script:PendingSearchArgs = $null
            $script:PendingSearchRequest = $false
            return
        }

        $script:CurrentItems = @($items)

        Fill-GridFromItems -items $script:CurrentItems -PreferredPaths $searchArgs.Preferred -FallbackIndex $searchArgs.Fallback

        try { Refresh-TagsFound } catch {}

        if ($script:DupModeEnabled -and -not $script:DupApplying) { Do-FindDuplicates }

        Debug-Log ("UI: filling grid with {0} items" -f (Get-Count $script:CurrentItems))

        Update-FoundCountStatus -UpdatingView:$UpdatingView
        Set-Info "Ready"

    } catch {

        Debug-Log ("Start-SearchSync: ERROR {0}" -f $_.Exception.Message)
        Set-Info "Ready"
        Set-Status "Search error"
        throw

    } finally {

        $script:IsSearching = $false
        try { Stop-Progress } catch {}

        # Re-enable UI
        try {
            try { $btnSearch.Enabled = $true } catch {}
            try { $btnBrowse.Enabled = $true } catch {}
            try { $btnHelp.Enabled   = $true } catch {}
            try { $comboTypes.Enabled = $true } catch {}
        } catch {}

        # If a search request arrived during search, run it now (unless user explicitly interrupted)
        if ($script:PendingSearchRequest -and $script:PendingSearchArgs) {
            $pa = $script:PendingSearchArgs
            $script:PendingSearchRequest = $false
            $script:PendingSearchArgs = $null
            try { Start-SearchSync -PreferredPaths $pa.Preferred -FallbackIndex $pa.Fallback -UpdatingView:([bool]$pa.UpdatingView) } catch { }
        }
    }
}



function Run-SearchAndFillGrid([string[]]$PreferredPaths, [int]$FallbackIndex, [switch]$ForceRefresh) {

    Start-SearchSync -PreferredPaths $PreferredPaths -FallbackIndex $FallbackIndex -ForceRefresh:$ForceRefresh

}



function Run-UpdateViewAndFillGrid([string[]]$PreferredPaths, [int]$FallbackIndex) {
    # Refresh current view after file operations, without implying criteria changed.
    # IMPORTANT: invalidate network scan cache so renamed/moved/tagged files are reflected immediately.
    try { Invalidate-DirScanCache ([string]$txtDir.Text) } catch { }
    Start-SearchSync -PreferredPaths $PreferredPaths -FallbackIndex $FallbackIndex -UpdatingView
}


function Add-SearchHistoryFromArgs([object]$args) {
    try {
        if ($null -eq $args) { return }
        # NOTE: keep history even for internal refreshes (avoids "No history yet")
        # if ([bool]$args.UpdatingView) { return }

        $entry = [PSCustomObject]@{
            When        = (Get-Date).ToString("s")
            Dir         = [string]$args.Dir
            BodyEnabled = [bool]$args.UseBody
            TagEnabled  = [bool]$args.UseTag
            BodyText    = [string]$args.BodyFilter
            TagText     = [string]$args.TagFilter
            TypeText    = [string](Get-SelectedTypeLabel $comboTypes)
            NoSubdirs   = [bool]$args.NoSubdirs
            MinSizeText = [string]$args.MinSizeText
            MaxSizeText = [string]$args.MaxSizeText
            AfterOn     = [bool]$args.AfterOn
            AfterDate   = if ($args.AfterDate) { [datetime]$args.AfterDate } else { $null }
            BeforeOn    = [bool]$args.BeforeOn
            BeforeDate  = if ($args.BeforeDate) { [datetime]$args.BeforeDate } else { $null }
            UseEverything = [bool]$args.UseEverything
        }

        if ($null -eq $script:SearchHistory) {
            $script:SearchHistory = New-Object System.Collections.ArrayList
        }

        # De-dup: if same as most recent, only refresh timestamp
        if ($script:SearchHistory.Count -gt 0) {
            $top = $script:SearchHistory[0]
            $same =
                ([string]$top.Dir -eq [string]$entry.Dir) -and
                ([bool]$top.BodyEnabled -eq [bool]$entry.BodyEnabled) -and
                ([bool]$top.TagEnabled -eq [bool]$entry.TagEnabled) -and
                ([string]$top.BodyText -eq [string]$entry.BodyText) -and
                ([string]$top.TagText -eq [string]$entry.TagText) -and
                ([string]$top.TypeText -eq [string]$entry.TypeText) -and
                ([bool]$top.NoSubdirs -eq [bool]$entry.NoSubdirs) -and
                ([string]$top.MinSizeText -eq [string]$entry.MinSizeText) -and
                ([string]$top.MaxSizeText -eq [string]$entry.MaxSizeText) -and
                ([bool]$top.AfterOn -eq [bool]$entry.AfterOn) -and
                ([bool]$top.BeforeOn -eq [bool]$entry.BeforeOn) -and
                ([bool]$top.UseEverything -eq [bool]$entry.UseEverything)

            if ($same) {
                try { $top.When = $entry.When } catch {}
                return
            }
        }

        # Insert at top
        [void]$script:SearchHistory.Insert(0, $entry)

        # Trim
        while ($script:SearchHistory.Count -gt [int]$script:SearchHistoryMax) {
            [void]$script:SearchHistory.RemoveAt($script:SearchHistory.Count - 1)
        }
    } catch { }
}

function Apply-SearchHistoryEntry([object]$h) {
    if ($null -eq $h) { return }
    $script:IsRestoring = $true
    try {
        if ($txtDir) { $txtDir.Text = [string]$h.Dir }
        if ($chkBody) { $chkBody.Checked = [bool]$h.BodyEnabled }
        if ($chkTag)  { $chkTag.Checked  = [bool]$h.TagEnabled }
        if ($txtBody) { $txtBody.Text = [string]$h.BodyText }
        if ($txtTag)  { $txtTag.Text  = [string]$h.TagText }
        if ($comboTypes -and $h.TypeText) {
            try { $comboTypes.SelectedItem = [string]$h.TypeText } catch { }
        }
        if ($chkNoSubdirs) { $chkNoSubdirs.Checked = [bool]$h.NoSubdirs }
        if ($txtMinSize) { $txtMinSize.Text = [string]$h.MinSizeText }
        if ($txtMaxSize) { $txtMaxSize.Text = [string]$h.MaxSizeText }

        if ($dtAfter) {
            $dtAfter.Checked = [bool]$h.AfterOn
            if ($h.AfterDate) { try { $dtAfter.Value = [datetime]$h.AfterDate } catch {} }
        }
        if ($dtBefore) {
            $dtBefore.Checked = [bool]$h.BeforeOn
            if ($h.BeforeDate) { try { $dtBefore.Value = [datetime]$h.BeforeDate } catch {} }
        }
        if ($chkEverything) { $chkEverything.Checked = [bool]$h.UseEverything }
    } finally {
        $script:IsRestoring = $false
    }
}

function Show-SearchHistoryDialog {
    try {
        if ($null -eq $script:SearchHistory -or $script:SearchHistory.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show($form, "No history yet.", "Search history", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            return
        }

        $dlg = New-Object System.Windows.Forms.Form
        $dlg.Text = "Search history"
        $dlg.StartPosition = "CenterParent"
        $dlg.Size = New-Object System.Drawing.Size(900, 450)
        $dlg.MinimizeBox = $false
        $dlg.MaximizeBox = $false

        $lb = New-Object System.Windows.Forms.ListBox
        $lb.Dock = "Fill"
        $lb.HorizontalScrollbar = $true

        foreach ($h in $script:SearchHistory) {
            $type = if ($h.TypeText) { [string]$h.TypeText } else { "" }
            $dir  = [string]$h.Dir
            $flags = @()
            if ([bool]$h.NoSubdirs) { $flags += "no subdirs" }
            if ([bool]$h.UseEverything) { $flags += "Everything" }
            if ([bool]$h.BodyEnabled) { $flags += "body" }
            if ([bool]$h.TagEnabled)  { $flags += "tags" }
            $f = if ($flags.Count -gt 0) { " [" + ($flags -join ", ") + "]" } else { "" }

            $lb.Items.Add(("{0} | {1} | {2}{3}" -f [string]$h.When, $type, $dir, $f)) | Out-Null
        }

        $panel = New-Object System.Windows.Forms.Panel
        $panel.Dock = "Bottom"
        $panel.Height = 45

        $btnApply = New-Object System.Windows.Forms.Button
        $btnApply.Text = "Apply"
        $btnApply.Width = 90
        $btnApply.Location = New-Object System.Drawing.Point(10, 10)

        $btnRun = New-Object System.Windows.Forms.Button
        $btnRun.Text = "Apply && Search"
        $btnRun.Width = 110
        $btnRun.Location = New-Object System.Drawing.Point(110, 10)

        $btnClose = New-Object System.Windows.Forms.Button
        $btnClose.Text = "Close"
        $btnClose.Width = 90
        $btnClose.Location = New-Object System.Drawing.Point(230, 10)

        $panel.Controls.Add($btnApply)
        $panel.Controls.Add($btnRun)
        $panel.Controls.Add($btnClose)

        $dlg.Controls.Add($lb)
        $dlg.Controls.Add($panel)

        $doApply = {
            $idx = $lb.SelectedIndex
            if ($idx -lt 0) { return $false }
            $h = $script:SearchHistory[$idx]
            Apply-SearchHistoryEntry $h
            return $true
        }

        $btnApply.Add_Click({
            if (& $doApply) { }
        })
        $btnRun.Add_Click({
            if (& $doApply) {
                $dlg.Close()
                Trigger-Search
            }
        })
        $btnClose.Add_Click({ $dlg.Close() })

        $lb.Add_DoubleClick({
            if (& $doApply) {
                $dlg.Close()
                Trigger-Search
            }
        })

        $dlg.ShowDialog($form) | Out-Null

    } catch { }
}



function Trigger-Search([switch]$ForceRefresh) {

    # Prevent re-entrancy (StrictMode-friendly) and avoid firing during settings restore

    if ($script:IsRestoring) {

        Debug-Log "Trigger-Search: restore in progress -> skipped"

        $script:PendingSearchRequest = $true

        return

    }

    if ($script:IsSearching) {

        Debug-Log "Trigger-Search: busy -> pending"

        $script:PendingSearchRequest = $true

        return

    }
    Run-SearchAndFillGrid -PreferredPaths @(Get-SelectedPaths) -FallbackIndex (Get-FirstSelectedIndex) -ForceRefresh:$ForceRefresh

}



# Tri par clic sur en-tête

$grid.Add_ColumnHeaderMouseClick({

    param($sender, $e)

    if ($script:CurrentItems -eq $null -or (Get-Count $script:CurrentItems) -le 1) { return }



    $col = $grid.Columns[$e.ColumnIndex]

    if ($null -eq $col) { return }

    $prop = $col.Name

    if ([string]::IsNullOrWhiteSpace($prop)) { return }



    $selPaths = @(Get-SelectedPaths)

    $fallback = Get-FirstSelectedIndex



    if ($script:SortColumnName -eq $prop) {

        $script:SortAscending = -not $script:SortAscending

    } else {

        $script:SortColumnName = $prop

        $script:SortAscending  = $true

    }



    if ($script:SortAscending) {

        $sorted = $script:CurrentItems | Sort-Object -Property $prop

    } else {

        $sorted = $script:CurrentItems | Sort-Object -Property $prop -Descending

    }

    $script:CurrentItems = @($sorted)



    Fill-GridFromItems -items $script:CurrentItems -PreferredPaths $selPaths -FallbackIndex $fallback -NoFitColumns

})



# ------------------------------ Settings capture/restore ------------------------------



function Capture-GridColumns {

    $cols = @()

    foreach ($c in $grid.Columns) {

        $cols += [PSCustomObject]@{

            Name         = $c.Name

            DisplayIndex = [int]$c.DisplayIndex

            Width        = [int]$c.Width

            Visible      = [bool]$c.Visible

        }

    }

    return $cols

}



function Apply-GridColumns($cols) {

    if ($null -eq $cols) { return }



    foreach ($cc in $cols) {

        try {

            $c = $grid.Columns[[string]$cc.Name]

            if ($null -eq $c) { continue }

            $c.Visible = [bool]$cc.Visible

            $c.Width   = [int]$cc.Width

        } catch {}

    }



    foreach ($cc in ($cols | Sort-Object DisplayIndex)) {

        try {

            $c = $grid.Columns[[string]$cc.Name]

            if ($null -ne $c) { $c.DisplayIndex = [int]$cc.DisplayIndex }

        } catch {}

    }

}



function Capture-Settings {

    $sel = @(Get-SelectedPaths)



    $firstRow = -1

    try { $firstRow = [int]$grid.FirstDisplayedScrollingRowIndex } catch { $firstRow = -1 }



    $hoff = 0

    try { $hoff = [int]$grid.HorizontalScrollingOffset } catch { $hoff = 0 }



    return [PSCustomObject]@{

        Window = [PSCustomObject]@{

            X      = [int]$form.Left

            Y      = [int]$form.Top

            Width  = [int]$form.Width

            Height = [int]$form.Height

        }

        Search = [PSCustomObject]@{

            Directory = [string]$txtDir.Text

            UseBody   = [bool]$chkBody.Checked

            Body      = [string]$txtBody.Text

            UseTag    = [bool]$chkTag.Checked

            Tag       = [string]$txtTag.Text

            FileType  = [string]$comboTypes.SelectedItem

        }

        Grid = [PSCustomObject]@{

            Columns          = Capture-GridColumns

            SelectedPaths    = $sel

            FirstRowIndex    = $firstRow

            HorizontalOffset = $hoff

        }

    }

}




# --- Settings autosave (window + grid) ---
if (-not (Get-Variable -Name SettingsDirty -Scope Script -ErrorAction SilentlyContinue)) { $script:SettingsDirty = $false }
if (-not (Get-Variable -Name AutoSaveTimer -Scope Script -ErrorAction SilentlyContinue)) { $script:AutoSaveTimer = $null }

function Mark-SettingsDirty {
    if ($script:RestoringSettings) { return }
    $script:SettingsDirty = $true

    # Re-lock row sizing after refills (prevents row-height resizing from coming back)
    try { Lock-GridRowSizing } catch { }
}


function Capture-SettingsSnapshot {
    $cfg = $script:Settings
    if ($cfg -eq $null) { $cfg = New-Settings; $script:Settings = $cfg }

    # Window
    try {
        $cfg.Window.X = [int]$form.Left
        $cfg.Window.Y = [int]$form.Top
        $cfg.Window.Width  = [int]$form.Width
        $cfg.Window.Height = [int]$form.Height
    } catch {}

    # Search
    try {
        $cfg.Search.Directory     = [string]$txtDir.Text
        $cfg.Search.BodyEnabled   = [bool]$chkBody.Checked
        $cfg.Search.TagEnabled    = [bool]$chkTag.Checked
        $cfg.Search.FileTypeLabel = [string]$cmbFileType.Text
        $cfg.Search.TagExpr       = [string]$txtTag.Text
        $cfg.Search.BodyExpr      = [string]$txtBody.Text
    } catch {}

    # Grid
    try { $cfg.Grid.Columns = Capture-GridColumns } catch {}

    return $cfg
}

    
function Show-InputBox([string]$title, [string]$prompt, [string]$default="") {

    return [Microsoft.VisualBasic.Interaction]::InputBox($prompt, $title, $default)

}



function Refresh-TagsFound {

    try {

        $script:SuppressFoundTagsEvent = $true

        $comboFoundTags.BeginUpdate()

        try {

            $comboFoundTags.Items.Clear()

            [void]$comboFoundTags.Items.Add("")



            # Toujours basé sur les résultats courants (évite une 2e récursion disque qui peut figer l'UI)

            $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

            if ($null -ne $script:CurrentItems) {

                foreach ($it in $script:CurrentItems) {

                    try {

                        $s = [string]$it.Tags

                        if ([string]::IsNullOrWhiteSpace($s)) { continue }

                        foreach ($t in ($s -split ",")) {

                            $tt = (Safe-TrimLower $t)

                            if ($tt -ne "") { [void]$set.Add($tt) }

                        }

                    } catch {}

                }

            }



            foreach ($t in (@($set) | Sort-Object)) { [void]$comboFoundTags.Items.Add($t) }

            # do not auto-select an item during refresh (avoids re-triggering search)

            $comboFoundTags.SelectedIndex = -1

        } finally {

            $comboFoundTags.EndUpdate()

            $script:SuppressFoundTagsEvent = $false

        }

    } catch {

        $script:SuppressFoundTagsEvent = $false

    }

}



function Do-AddTag {
    $script:PendingSelectionPaths = Get-SelectedPathsFromGrid


    if (-not (Ensure-OneOrMoreSelected)) { Set-Status "No selection."; return }

    $raw = Show-InputBox "Add tags" "Tags to add (comma separated):" ""

    $raw = Safe-TrimLower $raw

    if ($raw -eq "") { return }



    $add = @()

    foreach ($p in ($raw -split ",")) {

        $t = Safe-TrimLower $p

        if ($t -ne "") { $add += $t }

    }

    $add = Normalize-Tags $add

    if ((Get-Count $add) -eq 0) { return }



    $paths = @(Get-SelectedPaths)

    if ((Get-Count $paths) -eq 0) { return }



    $changed = 0; $skipped = 0; $failed = 0

    $newPreferred = New-Object System.Collections.Generic.List[string]



    foreach ($f in $paths) {

        try {

            $i = Get-Item -LiteralPath $f -ErrorAction Stop

            $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($i.Name)

            $body = Get-BodyFromNameNoExt $nameNoExt

            $tags = Normalize-Tags (Get-TagsFromNameNoExt $nameNoExt)



            $newTags = Normalize-Tags (@($tags) + @($add))

            $newName = Build-NewName -Body $body -Tags $newTags -Ext $i.Extension

            $newPath = Join-Path $i.DirectoryName $newName



            $res = Rename-FileSafe -OldPath $f -NewPath $newPath

            if ($res -eq "changed") {

                $changed++

                [void]$newPreferred.Add($newPath)

            } else {

                $skipped++

                [void]$newPreferred.Add($f)

            }

        } catch {

            $failed++

            [void]$newPreferred.Add($f)

        }

    }



    Set-OpStatus ("Add tags: changed {0}, skipped {1}, failed {2}" -f $changed,$skipped,$failed)



    Refresh-TagsFound

    Run-UpdateViewAndFillGrid -PreferredPaths @($newPreferred) -FallbackIndex (Get-FirstSelectedIndex)

}



function Do-RemoveTag {
    $script:PendingSelectionPaths = Get-SelectedPathsFromGrid


    if (-not (Ensure-OneOrMoreSelected)) { Set-Status "No selection."; return }



    $paths = @(Get-SelectedPaths)

    if ((Get-Count $paths) -eq 0) { return }



    $union = Get-UnionTagsFromFiles $paths

    if ((Get-Count $union) -eq 0) {

        [System.Windows.Forms.MessageBox]::Show($form, "No tags on selected file(s).", "Remove tags",

            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null

        return

    }



    $choice = Show-RemoveTagsDialog -Owner $form -AvailableTags $union

    if ($null -eq $choice) { return }



    $removeAll = [bool]$choice.RemoveAll

    $remove = @()

    if (-not $removeAll) {

        $remove = Normalize-Tags $choice.Tags

        if ((Get-Count $remove) -eq 0) { return }

    }



    $changed=0; $skipped=0; $failed=0

    $newPreferred = New-Object System.Collections.Generic.List[string]



    foreach ($f in $paths) {

        try {

            $i = Get-Item -LiteralPath $f -ErrorAction Stop

            $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($i.Name)

            $body = Get-BodyFromNameNoExt $nameNoExt

            $tags = Normalize-Tags (Get-TagsFromNameNoExt $nameNoExt)



            if ((Get-Count $tags) -eq 0) { $skipped++; [void]$newPreferred.Add($f); continue }



            $newTags = @()

            if (-not $removeAll) {

                foreach ($t in $tags) {

                    if (-not ($remove -contains $t)) { $newTags += $t }

                }

            }

            $newTags = Normalize-Tags $newTags



            $newName = Build-NewName -Body $body -Tags $newTags -Ext $i.Extension

            $newPath = Join-Path $i.DirectoryName $newName



            $res = Rename-FileSafe -OldPath $f -NewPath $newPath

            if ($res -eq "changed") {

                $changed++

                [void]$newPreferred.Add($newPath)

            } else {

                $skipped++

                [void]$newPreferred.Add($f)

            }

        } catch {

            $failed++

            [void]$newPreferred.Add($f)

        }

    }



    Set-OpStatus ("Remove tags: changed {0}, skipped {1}, failed {2}" -f $changed,$skipped,$failed)



    Refresh-TagsFound

    Run-UpdateViewAndFillGrid -PreferredPaths @($newPreferred) -FallbackIndex (Get-FirstSelectedIndex)

}



function Do-BodyRename {

    if (-not (Ensure-ExactlyOneSelected)) {

        [System.Windows.Forms.MessageBox]::Show($form, "Body rename works with exactly one selected file.", "Body rename",

            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null

        return

    }



    $p = @(Get-SelectedPaths)[0]

    if (-not (Test-Path -LiteralPath $p)) { Set-Status "File not found."; return }



    $i = Get-Item -LiteralPath $p -ErrorAction Stop

    $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($i.Name)

    $oldBody = Get-BodyFromNameNoExt $nameNoExt

    $tags = Normalize-Tags (Get-TagsFromNameNoExt $nameNoExt)



    $newBody = Show-InputBox "Body rename" "New body:" $oldBody

    if ($null -eq $newBody) { return }

    $newBody = $newBody.Trim()

    if ($newBody -eq "") { return }



    $changed = 0
    $skipped = 0
    $failed  = 0
    $preferred = New-Object System.Collections.Generic.List[string]

    try {

        $newName = Build-NewName -Body $newBody -Tags $tags -Ext $i.Extension

        $newPath = Join-Path $i.DirectoryName $newName

        $res = Rename-FileSafe -OldPath $p -NewPath $newPath

        if ($res -eq "changed") {
            $changed++
            [void]$preferred.Add($newPath)
        } else {
            $skipped++
            [void]$preferred.Add($p)
        }

        Set-OpStatus ("Body rename: changed {0}, skipped {1}, failed {2}" -f $changed,$skipped,$failed)



        Refresh-TagsFound

        Run-UpdateViewAndFillGrid -PreferredPaths @($preferred) -FallbackIndex (Get-FirstSelectedIndex)

    } catch {

        $failed++
        try { [void]$preferred.Add($p) } catch { }
        Set-OpStatus ("Body rename: changed {0}, skipped {1}, failed {2}" -f $changed,$skipped,$failed)

        [System.Windows.Forms.MessageBox]::Show($form, "Rename failed:`r`n$($_.Exception.Message)", "Body rename",

            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null

    }

}




function Do-CopyPath {

    if (-not (Ensure-OneOrMoreSelected)) { Set-Status "No selection."; return }

    $paths = @(Get-SelectedPaths)

    if ((Get-Count $paths) -eq 0) { return }

    $text = ($paths -join "`r`n")

    [System.Windows.Forms.Clipboard]::SetText($text)

    Set-Status ("Copied {0} path(s)" -f (Get-Count $paths))

}



function Execute-Paths([string[]]$paths) {

    foreach ($p in $paths) {

        try {

            Start-Process -FilePath $p | Out-Null

        } catch {

            [System.Windows.Forms.MessageBox]::Show($form, "Cannot open:`r`n$p`r`n`r`n$($_.Exception.Message)", "Execute",

                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null

        }

    }

}



function Do-Execute {

    if (-not (Ensure-OneOrMoreSelected)) { Set-Status "No selection."; return }

    $paths = @(Get-SelectedPaths)

    $n = (Get-Count $paths)

    if ($n -eq 0) { return }

    if ($n -gt 1) {

        $r = [System.Windows.Forms.MessageBox]::Show($form, "Open $n files?", "Execute",

            [System.Windows.Forms.MessageBoxButtons]::OKCancel, [System.Windows.Forms.MessageBoxIcon]::Question)

        if ($r -ne [System.Windows.Forms.DialogResult]::OK) { return }

    }

    Execute-Paths $paths

    Set-Status ("Executed {0} file(s)" -f $n)

}



function Do-OpenFolder {

    if (-not (Ensure-ExactlyOneSelected)) {

        [System.Windows.Forms.MessageBox]::Show($form, "Select exactly one file to open its folder.", "Open folder",

            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null

        return

    }



    $p = @(Get-SelectedPaths)[0]

    if (-not (Test-Path -LiteralPath $p)) { Set-Status "File not found."; return }



    try {

        $arg = "/select,""`"$p`""

        Start-Process explorer.exe $arg | Out-Null

    } catch {

        [System.Windows.Forms.MessageBox]::Show($form, "Cannot open folder:`r`n$($_.Exception.Message)", "Open folder",

            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null

    }

}





function Get-ImageDescription([string]$Path) {

    try {

        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue | Out-Null

        $img = [System.Drawing.Image]::FromFile($Path)

        try {

            $w = $img.Width

            $h = $img.Height

            $dpiX = [Math]::Round($img.HorizontalResolution)

            $dpiY = [Math]::Round($img.VerticalResolution)

            $bpp = [System.Drawing.Image]::GetPixelFormatSize($img.PixelFormat)

            return ("{0}x{1}, {2}x{3} ppp @ {4} bits" -f $w,$h,$dpiX,$dpiY,$bpp)

        } finally {

            $img.Dispose()

        }

    } catch {

        return $null

    }

}



function Get-ShellDetailsMap([string]$Path) {

    $map = @{}

    try {

        $shell = New-Object -ComObject Shell.Application

        $dir = [System.IO.Path]::GetDirectoryName($Path)

        $leaf = [System.IO.Path]::GetFileName($Path)

        $folder = $shell.Namespace($dir)

        if ($null -eq $folder) { return $map }

        $item = $folder.ParseName($leaf)

        if ($null -eq $item) { return $map }



        for ($i=0; $i -lt 320; $i++) {

            $name = [string]$folder.GetDetailsOf($null, $i)

            if ([string]::IsNullOrWhiteSpace($name)) { continue }

            $val = [string]$folder.GetDetailsOf($item, $i)

            if ([string]::IsNullOrWhiteSpace($val)) { continue }

            if (-not $map.ContainsKey($name)) { $map[$name] = $val }

        }

    } catch {}

    return $map

}




# ------------------------------ MediaInfo (optional) ------------------------------

$script:LastMediaInfoMissing = $false

function Find-MediaInfoExe {
    # Try to locate MediaInfo.exe in common install locations, PATH, and WinGet user packages.
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    try {
        foreach ($p in ($env:PATH -split ';')) {
            if (-not $p) { continue }
            $exe = Join-Path $p 'MediaInfo.exe'
            if (Test-Path -LiteralPath $exe) { [void]$candidates.Add($exe) }
        }
    } catch { }

    try {
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if (-not $root) { continue }
            foreach ($sub in @('MediaInfo','MediaArea\MediaInfo')) {
                $exe = Join-Path (Join-Path $root $sub) 'MediaInfo.exe'
                if (Test-Path -LiteralPath $exe) { [void]$candidates.Add($exe) }
            }
        }
    } catch { }

    # WinGet user packages (common on non-admin installs):
    try {
        if ($env:LOCALAPPDATA) {
            $wg = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
            if (Test-Path -LiteralPath $wg) {
                $hits = Get-ChildItem -LiteralPath $wg -Directory -Filter 'MediaArea.MediaInfo_*' -ErrorAction SilentlyContinue
                foreach ($h in $hits) {
                    $exe = Join-Path $h.FullName 'MediaInfo.exe'
                    if (Test-Path -LiteralPath $exe) { [void]$candidates.Add($exe) }
                }
            }
        }
    } catch { }

    foreach ($c in ($candidates | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    return $null
}

function Get-MediaInfoCliPath {
    # Returns a usable MediaInfo.exe path, or $null if not found.
    try {
        $p = Find-MediaInfoExe
        if ($p) { return $p }
    } catch { }
    return $null
}
function Get-SettingsDir {
    # User-scoped settings folder (no admin rights required)
    $base = $null

    if ($env:LOCALAPPDATA) {
        $base = Join-Path $env:LOCALAPPDATA $script:AppName
    } elseif ($env:APPDATA) {
        $base = Join-Path $env:APPDATA $script:AppName
    } else {
        # Fallback: alongside the script (should be rare)
        $base = Join-Path $PSScriptRoot $script:AppName
    }

    try {
        if (-not (Test-Path -LiteralPath $base)) {
            [void](New-Item -ItemType Directory -Path $base -Force -ErrorAction SilentlyContinue)
        }
    } catch { }

    return $base
}

function Get-SettingsPath {
    return (Join-Path (Get-SettingsDir) "settings.json")
}

function _Dbg([string]$msg) {
    try {
        if ($script:DebugMode) {
            $ts = (Get-Date).ToString("HH:mm:ss.fff")
            Write-Host ("[DEBUG {0}] {1}" -f $ts, $msg)
        }
    } catch {}
}

function Get-ObjProp {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Read-SettingsFile {
    $path = Get-SettingsPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { throw "empty json" }
        $cfg = $raw | ConvertFrom-Json -ErrorAction Stop
        # Minimal schema validation (strict)
        if ($null -eq $cfg) { throw "null cfg" }
        if (-not ($cfg.PSObject.Properties.Name -contains "Window")) { throw "missing Window" }
        if (-not ($cfg.PSObject.Properties.Name -contains "Search")) { throw "missing Search" }
        if (-not ($cfg.PSObject.Properties.Name -contains "Grid")) { throw "missing Grid" }
        return $cfg
    } catch {
        _Dbg ("Read-SettingsFile: ERROR {0} => deleting '{1}'" -f $_.Exception.Message, $path)
        try { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue } catch {}
        return $null
    }
}

function Apply-Settings([object]$cfg) {
    if ($null -eq $cfg) { return }

    $win = Get-ObjProp $cfg "Window"
    $search = Get-ObjProp $cfg "Search"
    $gridCfg = Get-ObjProp $cfg "Grid"

    $script:RestoringSettings = $true
    try {
        # ---- Window
        try {
            if ($win -and $form) {
                if ($win.Bounds) {
                    $b = $win.Bounds
                    if ($null -ne $b.X -and $null -ne $b.Y -and $null -ne $b.W -and $null -ne $b.H) {
                        $form.StartPosition = "Manual"
                        $form.Bounds = New-Object System.Drawing.Rectangle([int]$b.X,[int]$b.Y,[int]$b.W,[int]$b.H)
                        if ($form.WindowState -eq 'Normal') { Ensure-FormFitsScreen $form }
                    }
                }
                if ($win.State) {
                    try { $form.WindowState = [System.Windows.Forms.FormWindowState]::$($win.State) } catch {}
                }
            }
        } catch { _Dbg ("Restore-Settings: window restore error: {0}" -f $_.Exception.Message) }

        # ---- Search controls
        try {
            $s = $search
            if ($null -ne $s) {
                if ($txtDir -and ($s.PSObject.Properties.Name -contains "Dir")) { $txtDir.Text = [string]$s.Dir }
                if ($txtDir -and ($s.PSObject.Properties.Name -contains "RecentDirs")) {
                    try {
                        $txtDir.Items.Clear() | Out-Null
                        foreach ($d in @($s.RecentDirs)) {
                            $dd = Normalize-FSPath ([string]$d)
                            if (-not [string]::IsNullOrWhiteSpace($dd)) { [void]$txtDir.Items.Add($dd) }
                        }
                    } catch { }
                }

                if ($chkBody -and ($s.PSObject.Properties.Name -contains "BodyEnabled")) { $chkBody.Checked = [bool]$s.BodyEnabled }
                if ($chkTag  -and ($s.PSObject.Properties.Name -contains "TagEnabled"))  { $chkTag.Checked  = [bool]$s.TagEnabled }
                if ($txtBody -and ($s.PSObject.Properties.Name -contains "BodyText")) { $txtBody.Text = [string]$s.BodyText }
                if ($txtTag  -and ($s.PSObject.Properties.Name -contains "TagText"))  { $txtTag.Text  = [string]$s.TagText }

                if ($chkNoSubdirs -and ($s.PSObject.Properties.Name -contains "NoSubdirs")) { $chkNoSubdirs.Checked = [bool]$s.NoSubdirs }
                if ($txtMinSize -and ($s.PSObject.Properties.Name -contains "MinSizeText")) { $txtMinSize.Text = [string]$s.MinSizeText }
                if ($txtMaxSize -and ($s.PSObject.Properties.Name -contains "MaxSizeText")) { $txtMaxSize.Text = [string]$s.MaxSizeText }
                if ($dtAfter -and ($s.PSObject.Properties.Name -contains "AfterOn")) { $dtAfter.Checked = [bool]$s.AfterOn }
                if ($dtAfter -and ($s.PSObject.Properties.Name -contains "AfterDate")) { $dtAfter.Value = [datetime]$s.AfterDate }
                if ($dtBefore -and ($s.PSObject.Properties.Name -contains "BeforeOn")) { $dtBefore.Checked = [bool]$s.BeforeOn }
                if ($dtBefore -and ($s.PSObject.Properties.Name -contains "BeforeDate")) { $dtBefore.Value = [datetime]$s.BeforeDate }
                if ($chkEverything -and ($s.PSObject.Properties.Name -contains "UseEverything")) { 
        # Search history
        try {
            if ($s.PSObject.Properties.Name -contains "History") {
                if ($null -eq $script:SearchHistory) { $script:SearchHistory = New-Object System.Collections.ArrayList } else { $script:SearchHistory.Clear() }
                foreach ($h in @($s.History)) { [void]$script:SearchHistory.Add($h) }
            }
        } catch { }

$chkEverything.Checked = [bool]$s.UseEverything }
                if ($comboTypes -and ($s.PSObject.Properties.Name -contains "TypeText")) {
                    $t = [string]$s.TypeText
                    if (-not [string]::IsNullOrWhiteSpace($t)) {
                        $idx = -1
                        for ($i=0; $i -lt $comboTypes.Items.Count; $i++) {
                            if (($comboTypes.Items[$i] -as [string]) -eq $t) { $idx = $i; break }
                        }
                        if ($idx -ge 0) { $comboTypes.SelectedIndex = $idx }
                    }
                }
            }
        } catch { _Dbg ("Restore-Settings: search restore error: {0}" -f $_.Exception.Message) }

        # ---- Grid columns
        try {
            if ($grid -and $gridCfg -and $gridCfg.Columns) {
                foreach ($c in $gridCfg.Columns) {
                    if ($null -eq $c) { continue }
                    $name = $c.Name
                    if ([string]::IsNullOrWhiteSpace($name)) { continue }
                    if ($grid.Columns.Contains($name)) {
                        $col = $grid.Columns[$name]
                        if ($c.PSObject.Properties.Name -contains "Width") {
                            try { $col.Width = [int]$c.Width } catch {}
                        }
                        if ($c.PSObject.Properties.Name -contains "DisplayIndex") {
                            try { $col.DisplayIndex = [int]$c.DisplayIndex } catch {}
                        }
                    }
                }
            }
        
# Restore duplicates mode + selection (applied lazily after grid bind)
try {
    if ($cfg.PSObject.Properties.Match("Duplicates").Count -gt 0 -and $cfg.Duplicates) {
        try { $script:DupModeEnabled = [bool]$cfg.Duplicates.Enabled } catch { }
        try { $script:DupHideNonDuplicates = [bool]$cfg.Duplicates.HideNonDuplicates } catch { }
        try { $script:DupGroupByPath = [bool]$cfg.Duplicates.GroupByPath } catch { }
        try { Update-DuplicatesUI } catch { }
    }
} catch { }

try {
    if ($cfg.PSObject.Properties.Match("Selection").Count -gt 0 -and $cfg.Selection) {
        try { $script:PendingSelectionPaths = @($cfg.Selection.Paths) } catch { }
        try { $script:PendingSelectionCurrentPath = $cfg.Selection.CurrentPath } catch { }
    }
} catch { }

} catch { _Dbg ("Restore-Settings: grid restore error: {0}" -f $_.Exception.Message) }
    } finally {
        $script:RestoringSettings = $false
    }
}

function Collect-Settings {
    $cfg = [ordered]@{
        SchemaVersion = 1
        SavedAt = (Get-Date).ToString("s")
        Window = [ordered]@{
            State  = if ($form) { $form.WindowState.ToString() } else { "Normal" }
            Bounds = if ($form) {
                $b = if ($form.WindowState -eq [System.Windows.Forms.FormWindowState]::Normal) { $form.Bounds } else { $form.RestoreBounds }
                [ordered]@{ X=$b.X; Y=$b.Y; W=$b.Width; H=$b.Height }
            } else {
                [ordered]@{ X=0; Y=0; W=1200; H=800 }
            }
        }
        Search = [ordered]@{
            Dir         = if ($txtDir) { $txtDir.Text } else { "" }
            BodyEnabled = if ($chkBody) { [bool]$chkBody.Checked } else { $false }
            TagEnabled  = if ($chkTag)  { [bool]$chkTag.Checked } else { $false }
            BodyText    = if ($txtBody) { $txtBody.Text } else { "" }
            TagText     = if ($txtTag)  { $txtTag.Text } else { "" }
            TypeText    = if ($comboTypes -and $comboTypes.SelectedItem) { [string]$comboTypes.SelectedItem } else { "" }

            NoSubdirs   = if ($chkNoSubdirs) { [bool]$chkNoSubdirs.Checked } else { $false }
            MinSizeText = if ($txtMinSize) { $txtMinSize.Text } else { "" }
            MaxSizeText = if ($txtMaxSize) { $txtMaxSize.Text } else { "" }
            AfterOn     = if ($dtAfter)  { [bool]$dtAfter.Checked } else { $false }
            AfterDate   = if ($dtAfter)  { $dtAfter.Value } else { (Get-Date) }
            BeforeOn    = if ($dtBefore) { [bool]$dtBefore.Checked } else { $false }
            BeforeDate  = if ($dtBefore) { $dtBefore.Value } else { (Get-Date) }
            UseEverything = if ($chkEverything) { [bool]$chkEverything.Checked } else { $false }
            RecentDirs  = if ($txtDir -and $txtDir.Items) { @($txtDir.Items) } else { @() }
            History     = if ($script:SearchHistory) { @($script:SearchHistory) } else { @() }
        }
        Grid = [ordered]@{
            Columns = @()
        }
    }

    try {
        if ($grid) {
            foreach ($col in $grid.Columns) {
                try {
                    $cfg.Grid.Columns += [ordered]@{
                        Name = $col.Name
                        DisplayIndex = $col.DisplayIndex
                        Width = $col.Width
                    }
                } catch {}
            }
        }
    } catch {}
# Selection + duplicates mode
$selPaths = @()
$curPath = $null
try {
    if ($grid -and $grid.SelectedRows -and $grid.SelectedRows.Count -gt 0) {
        foreach ($r in $grid.SelectedRows) {
            try {
                $di = $r.DataBoundItem
                if ($di -and $di.PSObject.Properties.Match("Path").Count -gt 0 -and $di.Path) { $selPaths += [string]$di.Path }
                elseif ($di -and $di.PSObject.Properties.Match("FullPath").Count -gt 0 -and $di.FullPath) { $selPaths += [string]$di.FullPath }
                else {
                    try {
                        $p = $r.Cells["Path"].Value
                        if (-not $p) { $p = $r.Cells["FullPath"].Value }
                        if ($p) { $selPaths += [string]$p }
                    } catch { }
                }
            } catch { }
        }
    }
    if ($grid -and $grid.CurrentRow) {
        try {
            $di2 = $grid.CurrentRow.DataBoundItem
            if ($di2 -and $di2.PSObject.Properties.Match("Path").Count -gt 0 -and $di2.Path) { $curPath = [string]$di2.Path }
            elseif ($di2 -and $di2.PSObject.Properties.Match("FullPath").Count -gt 0 -and $di2.FullPath) { $curPath = [string]$di2.FullPath }
        } catch { }
        if (-not $curPath) {
            try {
                $p2 = $grid.CurrentRow.Cells["Path"].Value
                if (-not $p2) { $p2 = $grid.CurrentRow.Cells["FullPath"].Value }
                if ($p2) { $curPath = [string]$p2 }
            } catch { }
        }
    }
    $selPaths = @($selPaths | Where-Object { $_ } | Select-Object -Unique)
} catch { }


# Persist selection + duplicates mode
try {
    $cfg.Selection = [ordered]@{
        Paths   = @($selPaths)
        Current = $curPath
    }
    $cfg.Duplicates = [ordered]@{
        Enabled          = [bool]$script:DupModeEnabled
        HideNonDuplicates= [bool]$script:DupHideNonDuplicates
        GroupByPath      = [bool]$script:DupGroupByPath
    }
} catch {}

return $cfg

}


function Save-Settings {
    $path = Get-SettingsPath
    try {
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        $cfg = Collect-Settings
        $json = ($cfg | ConvertTo-Json -Depth 12 -Compress)
        # Write atomically
        $tmp = "$path.tmp"
        [System.IO.File]::WriteAllText($tmp, $json, [System.Text.Encoding]::UTF8)
        Move-Item -LiteralPath $tmp -Destination $path -Force
        _Dbg ("Save-Settings: OK path='{0}'" -f $path)
    } catch {
        _Dbg ("Save-Settings: ERROR {0} (path='{1}')" -f $_.Exception.Message, $path)
    }
}

function Restore-Settings {
    # Block searches/events until restore completes, then release and run any pending search request.
    $script:IsRestoring = $true
    try {
        $cfg = Read-SettingsFile
        if ($null -eq $cfg) { _Dbg "Restore-Settings: no cfg"; return }
        Apply-Settings $cfg
    } catch {
        _Dbg ("Restore-Settings: ERROR {0}" -f $_.Exception.Message)
    } finally {
        # Mark restore finished
        $script:IsRestoring = $false
        # Sync duplicates UI (button + menu) with restored state
        try {
            Update-DuplicateUi
            if (-not $script:DupModeEnabled -and -not $script:IsSearching) {
                Set-Info "Ready"
            }
        } catch { }
_Dbg "Restore-Settings: done"

        # If something tried to trigger a search during restore, run it now
        if ($script:PendingSearchRequest) {
            $script:PendingSearchRequest = $false
            try {
                if ($form -and -not $form.IsDisposed) {
                    [void]$form.BeginInvoke([Action]{ Trigger-Search })
                } else {
                    Trigger-Search
                }
            } catch { }
        }
    }
}

# --- Settings event wiring (strict) ---
# Restore ONCE on Shown (controls are created, columns exist). No other loads.

function Invoke-MediaInfoJson {
    param([Parameter(Mandatory)] [string]$Path)
    $exe = Get-MediaInfoCliPath
    if (-not $exe) { return $null }

    try {
        # MediaInfo CLI supports JSON output with --Output=JSON
        $json = & $exe "--Output=JSON" "--Full" "--Language=raw" "--" $Path 2>$null
        if ([string]::IsNullOrWhiteSpace($json)) { return $null }
        return ($json | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        return $null
    }
}

function Format-MediaInfoDuration {
    param([double]$Ms)
    if (-not $Ms -or $Ms -le 0) { return $null }
    $ts = [TimeSpan]::FromMilliseconds([math]::Round($Ms))
    if ($ts.TotalHours -ge 1) {
        return ("{0} h {1} min {2} sec" -f [int]$ts.TotalHours, $ts.Minutes, $ts.Seconds)
    }
    if ($ts.TotalMinutes -ge 1) {
        return ("{0} min {1} sec" -f [int]$ts.TotalMinutes, $ts.Seconds)
    }
    return ("{0} sec" -f [int]$ts.TotalSeconds)
}

function Try-GetVideoDescFromMediaInfo {
    param([Parameter(Mandatory)] [string]$Path)

    $mi = Invoke-MediaInfoJson -Path $Path
    if (-not $mi) { return $null }

    try {
        $tracks = @($mi.media.track)
        if (-not $tracks -or $tracks.Count -eq 0) { return $null }

        $general = $tracks | Where-Object { $_.'@type' -eq 'General' } | Select-Object -First 1
        $video   = $tracks | Where-Object { $_.'@type' -eq 'Video' }   | Select-Object -First 1

        $parts = @()

        # Duration
        $dur = $null
        if ($general -and $general.Duration) { $dur = [double]$general.Duration }
        if (-not $dur -and $video -and $video.Duration) { $dur = [double]$video.Duration }
        $durText = Format-MediaInfoDuration -Ms $dur
        if ($durText) { $parts += $durText }

        # Dimensions
        $w = $null; $h = $null
        if ($video) {
            if ($video.Width)  { $w = [int]($video.Width -replace '[^\d]','') }
            if ($video.Height) { $h = [int]($video.Height -replace '[^\d]','') }
        }
        if ($w -and $h) { $parts += ("{0}x{1}" -f $w, $h) }

        # Frame rate
        $fps = $null
        if ($video -and $video.FrameRate) { $fps = ($video.FrameRate -replace '[^0-9\.,]','') }
        if ($fps) { $parts += ("@ {0} fps" -f $fps) }

        # Bit rate
        $br = $null
        if ($general -and $general.OverallBitRate) { $br = ($general.OverallBitRate -replace '[^\d]','') }
        if (-not $br -and $video -and $video.BitRate) { $br = ($video.BitRate -replace '[^\d]','') }
        if ($br) {
            $brK = [math]::Round(([double]$br / 1000), 0)
            $parts += ("({0} kb/s)" -f $brK)
        }

        if ($parts.Count -gt 0) { return ($parts -join " ") }
    } catch {}

    return $null
}

function Get-VideoDescription([string]$Path) {

    $script:LastMediaInfoMissing = $false

    # 1) MediaInfo CLI (optional, best results)
    $miDesc = Try-GetVideoDescFromMediaInfo -Path $Path
    if ($miDesc) { return $miDesc }

    # If MediaInfo is not present, remember it so Do-Describe can show install instructions
    if (-not (Get-MediaInfoCliPath)) { $script:LastMediaInfoMissing = $true }

    # 2) Fallback: Windows Shell properties (often incomplete depending on codecs)
    try {

        $m = Get-ShellDetailsMap $Path

        if ($null -eq $m -or $m.Count -eq 0) { return $null }



        function Pick($keys) {

            foreach ($k in $keys) {

                foreach ($kk in $m.Keys) {

                    if ($kk -like $k) {

                        $v = $m[$kk]

                        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }

                    }

                }

            }

            return $null

        }



        $dur = Pick @("Duration*", "Length*")

        $w   = Pick @("Frame width*", "Width*")

        $h   = Pick @("Frame height*", "Height*")

        $fps = Pick @("Frame rate*")

        $br  = Pick @("Total bitrate*", "Bit rate*")



        $parts = @()

        if ($dur) { $parts += $dur }

        if ($w -and $h) { $parts += ("{0}x{1}" -f $w,$h) }

        if ($fps) { $parts += ("@ {0}" -f $fps) }

        if ($br)  { $parts += ("({0})" -f $br) }



        if ($parts.Count -gt 0) { return ($parts -join " ") }

    } catch {}

    return $null

}





function Try-GetAudioDescFromMediaInfo {
    param([Parameter(Mandatory)] [string]$Path)
    try {
        $j = Invoke-MediaInfoJson -Path $Path
        if (-not $j) { return $null }

        $tracks = $j.media.track
        if (-not $tracks) { return $null }

        $general = $tracks | Where-Object { $_.'@type' -eq 'General' } | Select-Object -First 1
        $audio   = $tracks | Where-Object { $_.'@type' -eq 'Audio' }   | Select-Object -First 1
        if (-not $audio) { return $null }

        # Duration
        $dur = $null
        $durMs = $null
        try { $durMs = [double]$general.Duration } catch {}
        if (-not $durMs) { try { $durMs = [double]$audio.Duration } catch {} }
        if ($durMs) {
            try {
                $ts = [TimeSpan]::FromMilliseconds($durMs)
                if ($ts.Hours -gt 0) { $dur = ("{0}h {1}m {2}s" -f $ts.Hours, $ts.Minutes, $ts.Seconds) }
                else { $dur = ("{0}m {1}s" -f $ts.Minutes, $ts.Seconds) }
            } catch {}
        }

        $artist = $null
        foreach ($k in @('Performer','Album_Performer','Composer','Artist')) {
            if (-not [string]::IsNullOrWhiteSpace($general.$k)) { $artist = [string]$general.$k; break }
            if (-not [string]::IsNullOrWhiteSpace($audio.$k)) { $artist = [string]$audio.$k; break }
        }

        $album = $null
        foreach ($k in @('Album','Album_More','Album/Performer')) {
            if (-not [string]::IsNullOrWhiteSpace($general.$k)) { $album = [string]$general.$k; break }
            if (-not [string]::IsNullOrWhiteSpace($audio.$k)) { $album = [string]$audio.$k; break }
        }

        $title = $null
        foreach ($k in @('Track_name','Title','Track')) {
            if (-not [string]::IsNullOrWhiteSpace($general.$k)) { $title = [string]$general.$k; break }
            if (-not [string]::IsNullOrWhiteSpace($audio.$k)) { $title = [string]$audio.$k; break }
        }

        $parts = @()
        if ($artist) { $parts += $artist }
        if ($album)  { $parts += $album }
        if ($title)  { $parts += $title }
        $line1 = ($parts -join " - ")
        if ([string]::IsNullOrWhiteSpace($line1)) { $line1 = "Audio metadata" }

        $line2Parts = @()
        if ($dur) { $line2Parts += $dur }

        $bitrate = $null
        try { $bitrate = [double]$audio.BitRate } catch {}
        if ($bitrate) { $line2Parts += ("{0} kb/s" -f [math]::Round($bitrate/1000)) }

        $sr = $null
        try { $sr = [int]$audio.SamplingRate } catch {}
        if ($sr) { $line2Parts += ("{0} Hz" -f $sr) }

        $ch = $null
        try { $ch = [int]$audio.Channels } catch {}
        if ($ch) { $line2Parts += ("{0} ch" -f $ch) }

        $line2 = ($line2Parts -join ", ")

        if ([string]::IsNullOrWhiteSpace($line2)) { return $line1 }
        return ($line1 + "`r`n" + $line2)
    } catch {
        return $null
    }
}

function Get-AudioDescription([string]$Path) {
    $script:LastMediaInfoMissing = $false

    $miDesc = Try-GetAudioDescFromMediaInfo -Path $Path
    if ($miDesc) { return $miDesc }

    # If MediaInfo is not present, remember it so Do-Describe can show install instructions (if we want later)
    $exe = Get-MediaInfoCliPath
    if (-not $exe) { $script:LastMediaInfoMissing = $true }

    # Fallback: Windows Shell properties (often works for MP3)
    try {
        $sh = New-Object -ComObject Shell.Application
        $dir = Split-Path -Parent $Path
        $leaf = Split-Path -Leaf $Path
        $folder = $sh.NameSpace($dir)
        if ($folder) {
            $item = $folder.ParseName($leaf)
            if ($item) {
                $dur = $folder.GetDetailsOf($item, 27) # Duration (varies by locale)
                $artist = $folder.GetDetailsOf($item, 13) # Contributing artists
                $album  = $folder.GetDetailsOf($item, 14) # Album
                $title  = $folder.GetDetailsOf($item, 21) # Title
                $line1Parts = @()
                if ($artist) { $line1Parts += $artist }
                if ($album)  { $line1Parts += $album }
                if ($title)  { $line1Parts += $title }
                $line1 = ($line1Parts -join " - ")
                $line2 = $dur
                if (-not [string]::IsNullOrWhiteSpace($line1) -and -not [string]::IsNullOrWhiteSpace($line2)) { return ($line1 + "`r`n" + $line2) }
                if (-not [string]::IsNullOrWhiteSpace($line1)) { return $line1 }
                if (-not [string]::IsNullOrWhiteSpace($line2)) { return $line2 }
            }
        }
    } catch {}

    return $null
}


function Get-ZipDescription([string]$Path) {

    try {

        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null

        $fs = [Int64](Get-Item -LiteralPath $Path).Length

        $real = 0L

        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)

        try {

            foreach ($e in $zip.Entries) {

                $real += [Int64]$e.Length

            }

        } finally {

            $zip.Dispose()

        }

        if ($real -le 0) { return $null }

        $ratio = 0.0

        if ($real -gt 0) { $ratio = 100.0 * (1.0 - ([double]$fs / [double]$real)) }

        return ("Real size = {0}, {1:n0}% compression ratio" -f (Format-FileSize $real), $ratio)

    } catch {

        return $null

    }

}



function Get-ExeDescription([string]$Path) {

    try {

        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)

        $prod = $vi.ProductName

        $ver  = $vi.ProductVersion

        if ([string]::IsNullOrWhiteSpace($prod) -and [string]::IsNullOrWhiteSpace($ver)) { return $null }

        if ([string]::IsNullOrWhiteSpace($prod)) { return ("v{0}" -f $ver) }

        if ([string]::IsNullOrWhiteSpace($ver))  { return $prod }

        return ("{0} v{1}" -f $prod, $ver)

    } catch { return $null }

}



function Do-Describe {

    if (-not (Ensure-ExactlyOneSelected)) {

        [System.Windows.Forms.MessageBox]::Show($form, "Description works with exactly one selected file.", "Description",

            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null

        return

    }



    $p = @(Get-SelectedPaths)[0]

    if ([string]::IsNullOrWhiteSpace($p) -or -not (Test-Path -LiteralPath $p)) { return }



    $ext = Safe-ToLower ([System.IO.Path]::GetExtension($p))

    $desc = $null



    # Best-effort by type

    if (@(".jpg",".jpeg",".png",".bmp",".gif",".tif",".tiff",".webp",".heic",".cr2",".nef",".arw",".dng",".orf",".raf") -contains $ext) {

        $desc = Get-ImageDescription $p

    } elseif (@(".avi",".mkv",".mov",".mp4",".mpg",".mpeg",".wmv",".m4v",".webm",".flv") -contains $ext) {

        $desc = Get-VideoDescription $p

    } elseif (@(".aac",".aiff",".alac",".flac",".m4a",".mp3",".ogg",".wav",".wma") -contains $ext) {

        $desc = Get-AudioDescription $p

    } elseif (@(".pdf",".docx",".xlsx",".pptx",".txt",".md",".csv",".tsv",".json",".xml",".yml",".yaml",".ini",".cfg",".log",".rtf",".ps1",".psm1",".psd1",".bat",".cmd",".reg") -contains $ext) {

        $desc = Get-DocumentDescription $p

    } elseif ($ext -eq ".zip") {

        $desc = Get-ZipDescription $p

    } elseif (@(".exe",".msi",".msix") -contains $ext) {

        $desc = Get-ExeDescription $p

    }
    if ([string]::IsNullOrWhiteSpace($desc)) {
        # If it is a video and we could not extract metadata, suggest installing MediaInfo CLI
        if ($script:LastMediaInfoMissing -and @(".mp4",".mkv",".mov",".avi",".wmv",".m4v",".webm",".flv",".mpg",".mpeg") -contains $ext) {
            $desc = "No video metadata available with the built-in Windows extractor on this system.`r`n`r`n" +
                    "Optional improvement: install MediaInfo CLI (mediainfo.exe).`r`n`r`n" +
                    "Install (Windows winget):`r`n  winget install -e --id MediaArea.MediaInfo`r`n`r`n" +
                    "Or download 'MediaInfo CLI' from MediaArea (mediaarea.net > MediaInfo > Download > Windows > CLI), then:`r`n" +
                    "  - put mediainfo.exe next to this script, or`r`n  - add it to PATH."
        } else {
            $desc = "No additional description available for this file."
        }
    }

# If it is a video and we could not extract metadata, suggest installing MediaInfo CLI
    if ([string]::IsNullOrWhiteSpace($desc) -and $script:LastMediaInfoMissing -and @(".mp4",".mkv",".mov",".avi",".wmv",".m4v",".webm",".mpg",".mpeg") -contains $ext) {
        $desc = "No video metadata available with the built-in Windows extractor on this system.`r`n`r`n" +
                "Optional improvement: install MediaInfo CLI (mediainfo.exe).`r`n`r`n" +
                "Install (Windows winget):`r`n  winget install -e --id MediaArea.MediaInfo`r`n`r`n" +
                "Or download 'MediaInfo CLI' from MediaArea (mediaarea.net > MediaInfo > Download > Windows > CLI), then:`r`n" +
                "  - put mediainfo.exe next to this script, or`r`n  - add it to PATH."
    }




    [System.Windows.Forms.MessageBox]::Show($form, $desc, "Description",

        [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null

}



function Do-DeleteFiles {
    $script:PendingSelectionPaths = Get-SelectedPathsFromGrid


    if (-not (Ensure-OneOrMoreSelected)) { Set-Status "No selection."; return }



    $paths = @(Get-SelectedPaths)

    if ((Get-Count $paths) -eq 0) { return }



    $list = ($paths | Select-Object -First 20) -join "`r`n"

    if ((Get-Count $paths) -gt 20) { $list += "`r`n... (+" + ((Get-Count $paths) - 20) + " more)" }



    $msg = "Delete the following file(s)?`r`n`r`n$list"

    $ans = [System.Windows.Forms.MessageBox]::Show($form, $msg, "Delete file(s)",

        [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)



    if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }



    $deleted=0; $failed=0

    foreach ($p in $paths) {

        try {

            Remove-Item -LiteralPath $p -Force -ErrorAction Stop

            $deleted++

        } catch {

            $failed++

        }

    }



    Set-OpStatus ("Delete: deleted {0}, failed {1}" -f $deleted,$failed)

    Refresh-TagsFound

    Run-UpdateViewAndFillGrid -PreferredPaths @() -FallbackIndex 0

}





# Copy tags (2-step)

$script:CopiedTags     = @()

$script:CopiedTagsFrom = $null



function Do-CopyTags {

    if ($null -eq $script:CopiedTagsFrom -or $script:CopiedTagsFrom -eq "") {

        if (-not (Ensure-ExactlyOneSelected)) {

            [System.Windows.Forms.MessageBox]::Show($form, "Select exactly one file to copy its tags first.", "Copy tags",

                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null

            return

        }



        $p = @(Get-SelectedPaths)[0]

        if (-not (Test-Path -LiteralPath $p)) { Set-Status "File not found."; return }



        try {

            $it = Get-Item -LiteralPath $p -ErrorAction Stop

            $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($it.Name)

            $script:CopiedTags = Normalize-Tags (Get-TagsFromNameNoExt $nameNoExt)

            if ((Get-Count $script:CopiedTags) -le 0) {
                # No tags -> do not start copy process
                $script:CopiedTags = @()
                $script:CopiedTagsFrom = ""
                [System.Windows.Forms.MessageBox]::Show($form, "Selected file has no tags to copy.", "Copy tags",
                    [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                return
            }

            if ((Get-Count $script:CopiedTags) -le 0) {
                # No tags on source file -> abort the copy-tags workflow
                $script:CopiedTags = @()
                $script:CopiedTagsFrom = ""
                [System.Windows.Forms.MessageBox]::Show($form, "The selected file has no tag to copy.", "Copy tags",
                    [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                return
            }

            $script:CopiedTagsFrom = $p

            Set-Status "Tags copied. Select target files, then press Copy tags again to apply."

        } catch {

            [System.Windows.Forms.MessageBox]::Show($form, "Cannot read selected file.", "Copy tags",

                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null

        }

        return

    }



    if (-not (Ensure-OneOrMoreSelected)) { return }

    $targets = @(Get-SelectedPaths | Where-Object { $_ -ne $script:CopiedTagsFrom })

    if ((Get-Count $targets) -eq 0) { Set-Status "No target selected."; return }



    $tagStr = if ((Get-Count $script:CopiedTags) -gt 0) { ($script:CopiedTags -join " + ") } else { "(no tags)" }

    $names  = @($targets | ForEach-Object { [System.IO.Path]::GetFileName($_) })

    $list   = ($names -join "`r`n")



    $msg = "Replace tags of these files with:`r`n$tagStr`r`n`r`nTargets:`r`n$list`r`n`r`nContinue?"

    $res = [System.Windows.Forms.MessageBox]::Show($form, $msg, "Copy tags",

        [System.Windows.Forms.MessageBoxButtons]::OKCancel, [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return }



    $changed=0; $skipped=0; $failed=0

    $newPreferred = New-Object System.Collections.Generic.List[string]



    foreach ($f in $targets) {

        try {

            $i = Get-Item -LiteralPath $f -ErrorAction Stop

            $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($i.Name)

            $body = Get-BodyFromNameNoExt $nameNoExt



            $newName = Build-NewName -Body $body -Tags $script:CopiedTags -Ext $i.Extension

            $newPath = Join-Path $i.DirectoryName $newName



            $r = Rename-FileSafe -OldPath $f -NewPath $newPath

            if ($r -eq "changed") {

                $changed++

                [void]$newPreferred.Add($newPath)

            } else {

                $skipped++

                [void]$newPreferred.Add($f)

            }

        } catch {

            $failed++

            [void]$newPreferred.Add($f)

        }

    }



    Set-OpStatus ("Copy tags: changed {0}, skipped {1}, failed {2}" -f $changed,$skipped,$failed)



    $script:CopiedTags = @()

    $script:CopiedTagsFrom = $null



    Refresh-TagsFound

    Run-UpdateViewAndFillGrid -PreferredPaths @($newPreferred) -FallbackIndex (Get-FirstSelectedIndex)

}



# ------------------------------ Help ------------------------------



function Show-Help {

    try {

        $helpForm = New-Object System.Windows.Forms.Form
        $helpForm.Text = "Aide - TagSearch"
        $helpForm.StartPosition = "CenterParent"
        $helpForm.Size = New-Object System.Drawing.Size(860, 620)
        $helpForm.MinimumSize = New-Object System.Drawing.Size(760, 520)
        $helpForm.KeyPreview = $true
        $helpForm.ShowInTaskbar = $false

        $helpForm.Add_KeyDown({
            param($s,$e)
            try {
                if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
                    $helpForm.Close()
                    $e.Handled = $true
                    $e.SuppressKeyPress = $true
                }
            } catch { }
        })

        $tabs = New-Object System.Windows.Forms.TabControl
        $tabs.Dock = "Fill"

        function Add-HelpTab([string]$title, [string]$content) {
            $tp = New-Object System.Windows.Forms.TabPage
            $tp.Text = $title

            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Multiline = $true
            $tb.ReadOnly = $true
            $tb.ScrollBars = "Vertical"
            $tb.WordWrap = $true
            $tb.Dock = "Fill"
            $tb.Font = New-Object System.Drawing.Font("Segoe UI", 10)
            $tb.Text = $content


            # Avoid showing text as selected/highlighted by default
            try { $tb.TabStop = $false } catch { }
            try { $tb.HideSelection = $true } catch { }
            try { $tb.SelectionStart = 0; $tb.SelectionLength = 0 } catch { }
            $tp.Controls.Add($tb)
            [void]$tabs.TabPages.Add($tp)
        }

        Add-HelpTab "Vue d'ensemble" @"
TagSearch - Aide detaillee

Cette application permet de rechercher des fichiers dans un dossier (et ses sous-dossiers),
puis d'agir sur la selection : ouvrir, ouvrir le dossier, lire une description, deplacer,
gerer des tags dans le nom, etc.

Navigation de l'aide :
- Utilisez les onglets en haut (plusieurs ecrans).
- Vous pouvez aussi utiliser " Precedent / Suivant " en bas.
- Echap ferme cette fenetre d'aide.

"@

        Add-HelpTab "Recherche" @"
1) Recherche

- Directory
  - Champ : dossier a analyser (recherche recursive).
  - Bouton " Browse... " : choisir un dossier.
  - Bouton " Search " : lance la recherche.
  - Bouton " Rescan " : relance la recherche avec les memes criteres.
  - Bouton " History " : accede aux recherches / dossiers recents.
  - Bouton " Help " : ouvre cette aide.


- Options avancees
  - Case "No subdirs" : ne scanne que le dossier courant (pas de sous-dossiers).
  - Min size / Max size : filtre de taille.
    - Formats acceptes : nombre d'octets (ex: 12345) OU suffixes K, M, G, T (ex: 500K, 20M, 2G, 1.5G).
    - K=1024, M=1024K, G=1024M, T=1024G.
  - After / Before : filtre sur la date de modification.
    - Cochez la case dans le champ date pour activer le filtre.

- Filtres
  - Case " Body " + champ : filtre sur le contenu / texte (selon vos regles internes du script).
  - Case " Tag " + champ : filtre sur les tags detectes dans le nom (entre parentheses).
    - Si le champ Tag est VIDE et la case Tag cochee : ne garder QUE les fichiers SANS tags.

- Type de fichiers
  - Liste deroulante : limite la recherche a certains types/extensions.

- Lancer une recherche
  - Bouton " Search " : lance la recherche.
  - Raccourci : Ctrl+Entree.

- Interrompre une recherche
  - Raccourci : Echap
  - Effet : stoppe la recherche en cours et affiche " Interrupted " en bas a droite.


- Option "Use Everything (fast)"
  - Peut accelerer la recherche sur de gros dossiers / reseaux si Everything est installe et en cours d'execution.
  - Installation (si absent) :
    1) Installer "Everything" (voidtools).
    2) Telecharger "ES" (Everything CLI) depuis voidtools (fichier es.exe) et le placer dans un dossier du PATH
       (ex: meme dossier que ce script, ou un dossier declare dans PATH).
  - Si Everything/ES n'est pas disponible, l'application revient automatiquement au scan standard.

- Barre de statut / progression
  - Lors d'operations lourdes (recherche, hash duplicates), une barre de progression et/ou un pourcentage peut apparaitre dans la barre de statut.
  - L'interface reste utilisable; la progression se met a jour sans figer l'application.

"@

        Add-HelpTab "Resultats" @"
2) Resultats et selection

- La grille affiche les fichiers trouves.
- Selection :
  - Clic : selectionne une ligne.
  - Ctrl+Clic / Shift+Clic : multi-selection.
  - Double-clic ou Entree : ouvre le fichier selectionne.

- Compteur
  - En bas a gauche : " Search: N file(s) found " reflete le nombre d'elements actuellement affiches.
  - En mode doublons (si vous masquez les non-doublons), ce compteur reflete aussi ce filtrage.

"@

        Add-HelpTab "Boutons" @"
3) Boutons d'actions (barre du bas)

- Execute file (Ctrl+E)
  - Execute/ouvre le fichier (equivalent au " Open " selon le type).

- Open folder (Ctrl+F)
  - Ouvre l'Explorateur Windows sur le dossier du fichier selectionne (selectionne dans Explorer).

- Description (Ctrl+D)
  - Affiche une description / apercu (selon le type : texte, docx, etc.) via l'action interne du script.

- Move file(s)... (Ctrl+M)
  - Deplace les fichiers selectionnes vers un dossier choisi.

- Show / Hide duplicates (Ctrl+U)
  - Affiche/masque le regroupement de doublons (selon l'heuristique du script).
  - A la sortie, la liste complete est restauree et le compteur se rafraichit.

- Copy path (Ctrl+C)
  - Copie les chemins des fichiers selectionnes dans le presse-papiers (un chemin par ligne).

- Add tags (Ctrl+A)
  - Ajoute des tags aux fichiers selectionnes (selon la logique de normalisation des tags du script).

- Remove tags (Ctrl+R)
  - Supprime des tags des fichiers selectionnes.

- Copy tags (Ctrl+T)
  - Copie la liste des tags detectes / presents dans le presse-papiers.

- Body rename (Ctrl+B)
  - Renommage " base sur Body " (selon votre logique existante).

"@

        Add-HelpTab "Menu contextuel" @"
4) Menu contextuel (clic droit dans la grille)

Le menu contextuel propose les memes actions que les boutons, avec les memes raccourcis :

- Execute file (Ctrl+E)
- Open folder (Ctrl+F)
- Description (Ctrl+D)
- Move file(s)... (Ctrl+M)
- Delete file(s) (Ctrl+L)
- Copy path (Ctrl+C)
- Body rename (Ctrl+B)
- Add tags (Ctrl+A)
- Remove tags (Ctrl+R)
- Copy tags (Ctrl+T)
- Help (Ctrl+H)

Astuce : les raccourcis fonctionnent meme sans ouvrir le menu, tant que la fenetre a le focus.

"@

        Add-HelpTab "Raccourcis" @"
5) Raccourcis clavier (recapitulatif)

Recherche / app :
- Ctrl+Entree : lancer la recherche
- Echap : interrompre la recherche en cours (status = Interrupted)
- Ctrl+H : ouvrir l'aide

Resultats / fichiers :
- Entree : ouvrir le fichier selectionne
- Ctrl+E : execute/open
- Ctrl+F : ouvrir le dossier
- Ctrl+D : description
- Ctrl+M : deplacer
- Ctrl+L : supprimer
- Ctrl+C : copier les chemins
- Ctrl+B : body rename
- Ctrl+A : add tags
- Ctrl+R : remove tags
- Ctrl+T : copy tags
- Ctrl+U : show/hide duplicates

"@

        Add-HelpTab "Doublons" @"
6) Mode doublons

Quand " Show duplicates " est active, le script :
- calcule des groupes de doublons (heuristique interne),
- peut regrouper / colorer les lignes,
- peut eventuellement masquer les non-doublons (si l'option est activee dans le script).

A la desactivation (" Hide duplicates ") :
- la liste complete de la derniere recherche est restauree,
- la grille est rafraichie,
- le compteur en bas a gauche reflete de nouveau la liste complete.

Le statut en bas a droite reste reserve a l'activite :
- Searching (press ESC to cancel)... pendant une recherche
- Working... pendant certaines operations longues
- Ready quand l'app ne fait rien
- Interrupted apres Echap.

"@

        Add-HelpTab "Depannage" @"
7) Depannage

- " Ready en permanence "
  - En recherche synchrone, le statut passe a " Searching (press ESC to cancel)... " au debut, puis " Ready " a la fin.
  - Si tu ne vois jamais " Searching... ", verifie que tu executes bien la derniere version du script.

- " Le pipeline a ete arrete "
  - Peut arriver si un evenement WinForms declenche une action pendant la fermeture.
  - Le script ignore explicitement certaines PipelineStoppedException la ou c'est approprie.

- Reglages (settings.json)
  - Charges au demarrage.
  - Sauvegardes a la fermeture.
  - Si JSON invalide : le fichier est supprime et l'app redemarre avec des valeurs par defaut.

"@

        # Bottom navigation bar
        $p = New-Object System.Windows.Forms.Panel
        $p.Dock = "Bottom"
        $p.Height = 44

        $btnPrev = New-Object System.Windows.Forms.Button
        $btnPrev.Text = "Precedent"
        $btnPrev.Width = 110
        $btnPrev.Height = 28
        $btnPrev.Left = 10
        $btnPrev.Top = 8

        $btnNext = New-Object System.Windows.Forms.Button
        $btnNext.Text = "Suivant"
        $btnNext.Width = 110
        $btnNext.Height = 28
        $btnNext.Left = 130
        $btnNext.Top = 8

        $btnClose = New-Object System.Windows.Forms.Button
        $btnClose.Text = "Fermer"
        $btnClose.Width = 110
        $btnClose.Height = 28
        $btnClose.Top = 8
        $btnClose.Anchor = "Top,Right"
        $btnClose.Left = $helpForm.ClientSize.Width - $btnClose.Width - 12
        $btnClose.Add_Click({ $helpForm.Close() })

        $p.Add_Resize({
            try { $btnClose.Left = $helpForm.ClientSize.Width - $btnClose.Width - 12 } catch { }
        })

        $btnPrev.Add_Click({
            try {
                if ($tabs.SelectedIndex -gt 0) { $tabs.SelectedIndex-- }
            } catch { }
        })

        $btnNext.Add_Click({
            try {
                if ($tabs.SelectedIndex -lt ($tabs.TabPages.Count - 1)) { $tabs.SelectedIndex++ }
            } catch { }
        })

        $tabs.Add_SelectedIndexChanged({
            try {
                $btnPrev.Enabled = ($tabs.SelectedIndex -gt 0)
                $btnNext.Enabled = ($tabs.SelectedIndex -lt ($tabs.TabPages.Count - 1))
            } catch { }
        })

        # initialize enabled state
        $btnPrev.Enabled = $false
        $btnNext.Enabled = ($tabs.TabPages.Count -gt 1)

        
        # Ensure help text is not shown as selected; keep focus on buttons, not the text area.
        try {
            $tabs.Add_SelectedIndexChanged({
                try {
                    $tpSel = $tabs.SelectedTab
                    if ($tpSel -ne $null) {
                        $tbSel = $null
                        foreach ($c in $tpSel.Controls) { if ($c -is [System.Windows.Forms.TextBox]) { $tbSel = $c; break } }
                        if ($tbSel -ne $null) { $tbSel.SelectionStart = 0; $tbSel.SelectionLength = 0 }
                    }
                } catch { }
                try { $btnClose.Focus() } catch { }
            })
        } catch { }

        $helpForm.Add_Shown({
            try {
                $tpSel = $tabs.SelectedTab
                if ($tpSel -ne $null) {
                    $tbSel = $null
                    foreach ($c in $tpSel.Controls) { if ($c -is [System.Windows.Forms.TextBox]) { $tbSel = $c; break } }
                    if ($tbSel -ne $null) { $tbSel.SelectionStart = 0; $tbSel.SelectionLength = 0 }
                }
            } catch { }
            try { $btnClose.Focus() } catch { }
        })

        $p.Controls.AddRange(@($btnPrev,$btnNext,$btnClose))

        $helpForm.Controls.Add($tabs)
        $helpForm.Controls.Add($p)

        [void]$helpForm.ShowDialog($form)

    } catch {
        # Fallback
        try {
            [System.Windows.Forms.MessageBox]::Show($form, $_.Exception.Message, "Help",
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        } catch { }
    }
}



# ------------------------------ Events / wiring ------------------------------



# Types de fichiers : tri alphabetique (Any file en tete)

$labels = @($script:FileTypeOptions | ForEach-Object { $_.Label })

$any = ($labels | Where-Object { $_ -like "Any file*" } | Select-Object -First 1)

$rest = @($labels | Where-Object { $_ -ne $any } | Sort-Object)



$script:IsInitializing = $true

$comboTypes.BeginUpdate()

try {

    $comboTypes.Items.Clear()

    if ($any) { [void]$comboTypes.Items.Add($any) }

    foreach ($l in $rest) { [void]$comboTypes.Items.Add($l) }

    if ($any -and $comboTypes.Items.Contains($any)) {

        $comboTypes.SelectedItem = $any

    } elseif ($comboTypes.Items.Count -gt 0) {

        $comboTypes.SelectedIndex = 0

    }

} finally {

    $comboTypes.EndUpdate()

}



$script:IsInitializing = $false

$comboTypes.Add_SelectedIndexChanged({
    if ($script:IsInitializing -or $script:IsRestoring) { return }
    try {
        $null = $form.BeginInvoke([Action]{ Trigger-Search })
    } catch [System.Management.Automation.PipelineStoppedException] {
        Debug-Log "comboTypes SelectedIndexChanged: PipelineStoppedException ignored"
    } catch {
        Debug-Log ("comboTypes SelectedIndexChanged: ERROR {0}" -f $_.Exception.Message)
    }
})



function Update-FilterControls {

    $txtBody.Enabled      = $chkBody.Checked

    $btnResetBody.Enabled = $chkBody.Checked

    $txtTag.Enabled       = $chkTag.Checked

    $btnResetTag.Enabled  = $chkTag.Checked

    $comboFoundTags.Enabled = $true

}



Update-FilterControls



$btnHelp.Add_Click({ Show-Help })



$btnBrowse.Add_Click({

    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog

    $dlg.Description = "Choose a folder to scan"

    $dlg.ShowNewFolderButton = $false

    if (-not [string]::IsNullOrWhiteSpace($txtDir.Text) -and (Test-Path -LiteralPath $txtDir.Text)) {

        $dlg.SelectedPath = $txtDir.Text

    }

    if ($dlg.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {

        $txtDir.Text = $dlg.SelectedPath

            Add-RecentDir $txtDir.Text
        Refresh-TagsFound

        Run-SearchAndFillGrid -PreferredPaths @() -FallbackIndex 0

    }

})



$btnResetBody.Add_Click({

    $txtBody.Text = ""

    Run-SearchAndFillGrid -PreferredPaths @() -FallbackIndex 0

})



$btnResetTag.Add_Click({

    $txtTag.Text = ""

    Run-SearchAndFillGrid -PreferredPaths @() -FallbackIndex 0

})



$btnSearch.Add_Click({

    Trigger-Search

})



# Enter dans Body / Tag relance la recherche

$txtBody.Add_KeyDown({

    param($sender,$e)

    if ($e.KeyCode -eq "Enter") {

        Run-SearchAndFillGrid -PreferredPaths @(Get-SelectedPaths) -FallbackIndex (Get-FirstSelectedIndex)

        $e.SuppressKeyPress = $true

    }

})



$txtTag.Add_KeyDown({

    param($sender,$e)

    if ($e.KeyCode -eq "Enter") {

        Run-SearchAndFillGrid -PreferredPaths @(Get-SelectedPaths) -FallbackIndex (Get-FirstSelectedIndex)

        $e.SuppressKeyPress = $true

    }

})



$btnExecute.Add_Click({ Do-Execute })



# ------------------------------ Move files ------------------------------

function Do-MoveFiles {
    $script:PendingSelectionPaths = Get-SelectedPathsFromGrid

    $paths = @(Get-SelectedPaths)
    $fallbackIndex = (Get-FirstSelectedIndex)
    $newPreferred = New-Object System.Collections.Generic.List[string]
    if ((Get-Count $paths) -le 0) { Show-Status "No file selected." ; return }

    $first = $paths[0]
    $startDir = $null
    try { $startDir = [System.IO.Path]::GetDirectoryName($first) } catch {}
    if (-not $startDir) { $startDir = $script:CurrentDirectory }

    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Select destination folder"
    $dlg.SelectedPath = $startDir
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $destDir = $dlg.SelectedPath
    if (-not (Test-Path -LiteralPath $destDir -PathType Container)) { Show-Error "Destination folder not found."; return }

    # Preflight collisions
    $collisions = @()
    foreach ($p in $paths) {
        try {
            $name = [System.IO.Path]::GetFileName($p)
            $dest = Join-Path -Path $destDir -ChildPath $name
            if (Test-Path -LiteralPath $dest) { $collisions += $dest }
        } catch {}
    }

    $overwrite = $false
    if ((Get-Count $collisions) -gt 0) {
        $list = ($collisions | Select-Object -First 10) -join "`r`n"
        if ((Get-Count $collisions) -gt 10) { $list += "`r`n... (+$((Get-Count $collisions)-10) more)" }
        $msg = "Some destination files already exist:`r`n`r`n$list`r`n`r`nOverwrite them?"
        $res = [System.Windows.Forms.MessageBox]::Show($msg, "Move file(s)", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($res -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $overwrite = $true
    }

    $moved = 0
    foreach ($p in $paths) {
        try {
            $name = [System.IO.Path]::GetFileName($p)
            $dest = Join-Path -Path $destDir -ChildPath $name
            if ($overwrite -and (Test-Path -LiteralPath $dest)) {
                Remove-Item -LiteralPath $dest -Force -ErrorAction Stop
            }
            Move-Item -LiteralPath $p -Destination $destDir -Force -ErrorAction Stop
            $moved++
            try { [void]$newPreferred.Add((Join-Path -Path $destDir -ChildPath $name)) } catch { }
        } catch {
            Show-Error ("Move failed: {0}" -f $_.Exception.Message)
            break
        }
    }

    Set-OpStatus ("Moved {0} file(s) to {1}" -f $moved, $destDir)
    Run-UpdateViewAndFillGrid -PreferredPaths @($newPreferred) -FallbackIndex $fallbackIndex
}

# ------------------------------ Duplicate detection ------------------------------

$script:DuplicateColorsEnabled = $false

function Clear-DuplicateColors {
    try {
        foreach ($r in $grid.Rows) {
            try { $r.DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty } catch {}
        }
    } catch {}
    $script:DuplicateColorsEnabled = $false
}

function Get-ItemMediaSignature($item) {
    # Returns a string signature to refine duplicates inside same-size groups
    try {
        $path = [string]$item.Path
        $ext = Safe-ToLower ([System.IO.Path]::GetExtension($path))
        if ($ext -in @(".jpg",".jpeg",".png",".bmp",".gif",".tif",".tiff",".webp")) {
            try {
                $img = [System.Drawing.Image]::FromFile($path)
                try { return ("img:{0}x{1}" -f $img.Width, $img.Height) } finally { $img.Dispose() }
            } catch { return "img:?" }
        }

        $mi = Get-MediaInfoCliPath
        if ($mi -and ($ext -in @(".mp4",".mkv",".avi",".mov",".wmv",".mpg",".mpeg",".m4v",".webm",".mp3",".flac",".wav",".m4a",".aac",".ogg",".wma"))) {
            try {
                $json = & $mi "--Output=JSON" "--Language=raw" $path 2>$null
                if ($LASTEXITCODE -eq 0 -and $json) {
                    $o = $json | ConvertFrom-Json -ErrorAction Stop
                    $tracks = $o.media.track
                    $v = $tracks | Where-Object { $_."@type" -eq "Video" } | Select-Object -First 1
                    $a = $tracks | Where-Object { $_."@type" -eq "Audio" } | Select-Object -First 1
                    if ($v) {
                        $dur = $v.Duration; $w=$v.Width; $h=$v.Height
                        return ("vid:{0}:{1}x{2}" -f $dur,$w,$h)
                    }
                    if ($a) {
                        $dur = $a.Duration; $br=$a.BitRate
                        return ("aud:{0}:{1}" -f $dur,$br)
                    }
                }
            } catch {}
        }
    } catch {}
    return "other"
}


function Update-DuplicatesUI {
    # Backward-compatible wrapper (older code called Update-DuplicatesUI)
    # Keep all UI updates in Update-DuplicateUi which is driven by $script:DupModeEnabled.
    try { Update-DuplicateUi } catch {}
    try { Update-FoundCountStatus } catch {}
}

function Do-ToggleDuplicates {
    # Switching view mode -> clear any previous operation summary in the left status
    try { Clear-OpStatus } catch { }

    # Toggle duplicate visualization (and filtering/grouping of non-duplicates)
    if (-not $script:DupModeEnabled) {

        # Save the current full result list so we can restore it when leaving duplicates mode.
        # (Duplicates mode may reorder and/or filter $script:CurrentItems.)
        try { $script:DupSavedItems = @($script:CurrentItems) } catch { $script:DupSavedItems = $null }

        $script:DupModeEnabled = $true
        if ($null -eq $script:DupHideNonDuplicates) { $script:DupHideNonDuplicates = $true }
        Do-FindDuplicates

        # Refresh main status line with the current displayed result count
        try { Update-FoundCountStatus -UpdatingView } catch { }

    } else {

        $script:DupModeEnabled = $false

        # Restore original item list (pre-duplicates), if we saved it.
        if ($null -ne $script:DupSavedItems) {
            try {
                $script:CurrentItems = @($script:DupSavedItems)
            } catch { }
            $script:DupSavedItems = $null

            # Refill grid in the original order (do not auto-fit columns; keep user layout)
            $script:DupApplying = $true
            try { Fill-GridFromItems -Items $script:CurrentItems -NoFitColumns } finally { $script:DupApplying = $false }
        }
        elseif ($null -ne $script:LastSearchItems -and (Get-Count $script:LastSearchItems) -gt 0) {
            # If duplicates mode was already enabled on startup (restored from settings),
            # we may not have a saved list. Restore from the last full search results.
            try { $script:CurrentItems = @($script:LastSearchItems) } catch { }

            $script:DupApplying = $true
            try { Fill-GridFromItems -Items $script:CurrentItems -NoFitColumns } finally { $script:DupApplying = $false }
        }
        else {
            # Fallback: restore visibility and clear coloring on current rows
            foreach ($row in $grid.Rows) {
                $row.Visible = $true
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty
            }
        }

        $script:DupGroupMap = @{}
        $script:DupTotal = 0
        Update-DuplicateUi

        # Refresh main status line with the current displayed result count
        try { Update-FoundCountStatus -UpdatingView } catch { }
}
}


function Update-DuplicateUi {
    # Button + context menu label and right status area
    if ($script:DupModeEnabled) {
        foreach ($c in @($grid.Columns)) { try { $c.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable } catch {} }
        $btnDup.Text = "Hide d&uplicates (Ctrl+U)"
        if ($script:CtxDupItem) { $script:CtxDupItem.Text = "Hide d&uplicates (Ctrl+U)" }
        # Avoid inline (if ..) subexpression because some environments end up invoking it as a string
        $dupN = 0
        if ($null -ne $script:DupTotal) {
            try { $dupN = [int]$script:DupTotal } catch { $dupN = 0 }
        }
        # Bottom-right is reserved for activity (Searching/Ready). Do not overwrite with counts.
        if (-not $script:IsSearching) { Set-Info "Ready" }
} else {
        foreach ($c in @($grid.Columns)) { try { $c.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::Automatic } catch {} }
        $btnDup.Text = "Show d&uplicates (Ctrl+U)"
        if ($script:CtxDupItem) { $script:CtxDupItem.Text = "Show d&uplicates (Ctrl+U)" }
        # Clear duplicates info; caller (search) can set Searching/Done as needed
        if (-not $script:IsSearching) { Set-Info "Ready" }
    }
}



function Get-FileSha256Cached([string]$Path) {
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
        $fi = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $fi) { return $null }

        $size = [int64]$fi.Length
        $lw   = [datetime]$fi.LastWriteTimeUtc

        $cached = $null
        if ($script:FileHashCache -and $script:FileHashCache.ContainsKey($Path)) {
            $cached = $script:FileHashCache[$Path]
        }
        if ($cached -and $cached.Hash -and ($cached.Size -eq $size) -and ($cached.LastWriteUtc -eq $lw)) {
            return [string]$cached.Hash
        }

        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $hashBytes = $sha.ComputeHash($fs)
            } finally {
                $fs.Dispose()
            }
        } finally {
            $sha.Dispose()
        }
        $hash = ([System.BitConverter]::ToString($hashBytes)).Replace("-", "").ToLowerInvariant()

        try {
            $script:FileHashCache[$Path] = [PSCustomObject]@{
                Hash = $hash
                Size = $size
                LastWriteUtc = $lw
            }
        } catch { }

        return $hash
    } catch {
        return $null
    }
}


# ------------------------------ Duplicates (async hash to avoid UI freeze) ------------------------------

$script:DupWorker = $null
$script:DupComputeToken = $null

function Ensure-DuplicateWorker {
    try {
        if ($script:DupWorker) { return }

        $bw = New-Object System.ComponentModel.BackgroundWorker
        $bw.WorkerSupportsCancellation = $true

        $bw.add_DoWork({
            param($sender, $e)

            $a = $e.Argument

            $prevRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
            [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace = $script:MainRunspace

            try {
                $token = [string]$a.Token
                $items = @($a.Items)
                $useHash = [bool]$a.UseHash

                # Build candidate groups by (size + ext), using cached SizeBytes when present to avoid network metadata hits.
                $groups = @{}
                foreach ($it in $items) {
                    if ($sender.CancellationPending) { $e.Cancel = $true; return }

                    $p = [string]$it.Path
                    if ([string]::IsNullOrWhiteSpace($p)) { continue }

                    $size = 0
                    try {
                        if ($it -and ($it.PSObject.Properties.Name -contains "SizeBytes")) {
                            $size = [int64]$it.SizeBytes
                        }
                    } catch { $size = 0 }

                    if ($size -le 0) {
                        $fi = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
                        if ($null -eq $fi) { continue }
                        $size = [int64]$fi.Length
                    }

                    $ext = [string]([System.IO.Path]::GetExtension($p))
                    $key = "{0}|{1}" -f $size, ($ext.ToLowerInvariant())

                    if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.Generic.List[string] }
                    [void]$groups[$key].Add($p)
                }

                $dupMap = @{}
                $groupId = 0

                foreach ($k in $groups.Keys) {
                    if ($sender.CancellationPending) { $e.Cancel = $true; return }

                    $list = $groups[$k]
                    if ($null -eq $list -or $list.Count -lt 2) { continue }

                    if (-not $useHash) {
                        foreach ($p in $list) { $dupMap[[string]$p] = $groupId }
                        $groupId++
                        continue
                    }

                    # Hash-confirm within this candidate group (same size+ext)
                    $hgroups = @{}
                    foreach ($p in $list) {
                        if ($sender.CancellationPending) { $e.Cancel = $true; return }

                        $h = Get-FileSha256Cached -Path ([string]$p)
                        if (-not $h) { continue }

                        if (-not $hgroups.ContainsKey($h)) { $hgroups[$h] = New-Object System.Collections.Generic.List[string] }
                        [void]$hgroups[$h].Add([string]$p)
                    }

                    foreach ($h in $hgroups.Keys) {
                        if ($sender.CancellationPending) { $e.Cancel = $true; return }

                        $sub = $hgroups[$h]
                        if ($null -ne $sub -and $sub.Count -ge 2) {
                            foreach ($p in $sub) { $dupMap[[string]$p] = $groupId }
                            $groupId++
                        }
                    }
                }

                # Total "duplicate files" shown: count of items that are in a dup group.
                $dupTotal = 0
                foreach ($it in $items) {
                    $p = [string]$it.Path
                    if ($dupMap.ContainsKey($p)) { $dupTotal++ }
                }

                $e.Result = [PSCustomObject]@{
                    Token = $token
                    Map   = $dupMap
                    Total = $dupTotal
                }

            } catch {
                $e.Result = [PSCustomObject]@{
                    Token = [string]$a.Token
                    Map   = @{}
                    Total = 0
                    Error = $_.Exception.Message
                }
            } finally {
                [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace = $prevRunspace
            }
        })

        $bw.add_RunWorkerCompleted({
            param($sender, $e)
            try {
                if ($e.Cancelled) {
                    try { $script:IsHashingDuplicates = $false } catch { }
                    try { Stop-Progress } catch { }
                    if (-not $script:IsSearching) { try { Set-Info "Ready" } catch { } }
                    return
                }
                if ($e.Error) {
                    try { $script:IsHashingDuplicates = $false } catch { }
                    try { Stop-Progress } catch { }
                    Debug-Log ("DupWorker: error: {0}" -f $e.Error.Exception.Message)
                    if (-not $script:IsSearching) { try { Set-Info "Ready" } catch { } }
                    return
                }

                $res = $e.Result
                if ($null -eq $res) { return }

                # Ignore stale results
                if ($script:DupComputeToken -and ([string]$res.Token -ne [string]$script:DupComputeToken)) {
                    return
                }

                $script:DupGroupMap = @{}
                try { $script:DupGroupMap = $res.Map } catch { $script:DupGroupMap = @{} }

                try { $script:DupTotal = [int]$res.Total } catch { $script:DupTotal = 0 }

                Apply-DuplicateUiFromMap
                    try { $script:IsHashingDuplicates = $false } catch { }
                    try { Stop-Progress } catch { }
            } catch { }
        })

        $script:DupWorker = $bw
    } catch { }
}

function Cancel-DuplicateWorker {
    try {
        if ($script:DupWorker -and $script:DupWorker.IsBusy) {
            $script:DupWorker.CancelAsync() | Out-Null
        }
            try { $script:IsHashingDuplicates = $false } catch { }
            try { Stop-Progress } catch { }
            try { Set-Info "Ready" } catch { }
    } catch { }
}

function Apply-DuplicateUiFromMap {
    try {
        # If duplicates mode is ON, reorder items so duplicates are grouped (and optionally hide non-dup).
        if ($script:DupModeEnabled) {
            if ($script:DupHideNonDuplicates) {
                $script:CurrentItems = @(
                    $script:CurrentItems | Where-Object { $script:DupGroupMap.ContainsKey([string]$_.Path) } |
                    Sort-Object -Property @{ Expression = { $script:DupGroupMap[[string]$_.Path] } }, Path
                )
            } else {
                $script:CurrentItems = @(
                    $script:CurrentItems |
                    Sort-Object -Property @{ Expression = { if ($script:DupGroupMap.ContainsKey([string]$_.Path)) { $script:DupGroupMap[[string]$_.Path] } else { [int]::MaxValue } } }, Path
                )
            }

            # Refill grid in grouped order (no fitting here; keep users layout)
            $script:DupApplying = $true
            try { Fill-GridFromItems -Items $script:CurrentItems -NoFitColumns } finally { $script:DupApplying = $false }
        }

        # Apply row coloring + visibility
        foreach ($row in $grid.Rows) {
            $p = [string]$row.Cells["Path"].Value
            $isDup = $script:DupGroupMap.ContainsKey($p)

            # Visibility rule
            if ($script:DupModeEnabled -and $script:DupHideNonDuplicates) {
                $row.Visible = $isDup
            } else {
                $row.Visible = $true
            }

            # Reset style first
            $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Empty

            if ($isDup) {
                $g = [int]$script:DupGroupMap[$p]
                $colors = @(
                    [System.Drawing.Color]::LightYellow,
                    [System.Drawing.Color]::LightCyan,
                    [System.Drawing.Color]::MistyRose,
                    [System.Drawing.Color]::Honeydew,
                    [System.Drawing.Color]::Lavender,
                    [System.Drawing.Color]::LightGoldenrodYellow,
                    [System.Drawing.Color]::AliceBlue
                )
                $row.DefaultCellStyle.BackColor = $colors[$g % $colors.Count]
            }
        }

        Update-DuplicateUi
        if (-not $script:IsSearching) { Set-Info "Ready" }
    } catch { }
}


function Do-FindDuplicates {
    # Computes potential duplicates in current results and (optionally) colors + hides rows.
    # Default heuristic: same size + extension. If 'Hash duplicates' is enabled, we additionally confirm
    # within candidate groups using SHA-256. Hashing can be slow on large/network files, so it runs async.

    if (-not $script:IsSearching) { Set-Info "Working..." }

    if ($null -eq $script:CurrentItems -or $script:CurrentItems.Count -eq 0) {
        # Nothing to do (no error)
        $script:DupGroupMap = @{}
        $script:DupTotal = 0
        Apply-DuplicateUiFromMap
        return
    }

    # Hash mode: run in background to keep UI responsive (avoid "freeze/minimize" on network shares)
    if ($script:DupUseHash -and -not $script:IsSearching) {
        Ensure-DuplicateWorker

        # Cancel any in-flight computation, then start a new one
        Cancel-DuplicateWorker

        $token = [guid]::NewGuid().ToString()
        $script:DupComputeToken = $token

        try { Set-Info "Hashing duplicates..." } catch { }

        $script:IsHashingDuplicates = $true
        Start-Progress -Text "Hashing duplicates..." -Marquee -NoPercent
        try {
            $script:DupWorker.RunWorkerAsync([PSCustomObject]@{
                Token   = $token
                Items   = @($script:CurrentItems)
                UseHash = $true
            }) | Out-Null
        } catch {
            # Fallback: if worker failed to start, compute without hash synchronously
            $script:DupUseHash = $false
        }

        return
    }

    # Synchronous (size + ext only), using cached metadata (SizeBytes) to avoid expensive Get-Item on network.
    $groups = @{}
    foreach ($it in $script:CurrentItems) {
        try {
            $p = [string]$it.Path
            if ([string]::IsNullOrWhiteSpace($p)) { continue }

            $size = 0
            try {
                if ($it -and ($it.PSObject.Properties.Name -contains "SizeBytes")) {
                    $size = [int64]$it.SizeBytes
                }
            } catch { $size = 0 }

            if ($size -le 0) {
                $fi = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
                if ($null -eq $fi) { continue }
                $size = [int64]$fi.Length
            }

            $ext  = [string]([System.IO.Path]::GetExtension($p))
            $key  = "{0}|{1}" -f $size, ($ext.ToLowerInvariant())

            if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.Generic.List[string] }
            [void]$groups[$key].Add($p)
        } catch {
            # ignore unreadable entries
        }
    }

    $script:DupGroupMap = @{}
    $groupId = 0

    foreach ($k in $groups.Keys) {
        $list = $groups[$k]
        if ($null -eq $list -or $list.Count -lt 2) { continue }

        foreach ($p in $list) { $script:DupGroupMap[[string]$p] = $groupId }
        $groupId++
    }

    # Total "duplicate files" shown: count of items that are in a dup group.
    $script:DupTotal = 0
    foreach ($it in $script:CurrentItems) {
        if ($script:DupGroupMap.ContainsKey([string]$it.Path)) { $script:DupTotal++ }
    }

    Apply-DuplicateUiFromMap
}





# ------------------------------ Document description (Ctrl+D) ------------------------------

function Get-ZipXmlEntry {
    param([string]$ZipPath, [string]$EntryName)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        try {
            $e = $zip.Entries | Where-Object { $_.FullName -eq $EntryName } | Select-Object -First 1
            if (-not $e) { return $null }
            $sr = New-Object System.IO.StreamReader($e.Open())
            try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
        } finally { $zip.Dispose() }
    } catch { return $null }
}

function Get-DocumentDescription([string]$Path) {
    $ext = Safe-ToLower ([System.IO.Path]::GetExtension($Path))

    if (@(".txt",".log",".csv",".md",".ini",".cfg",".json",".xml",".yml",".yaml",".ps1",".psm1",".psd1",".bat",".cmd",".reg",".sql") -contains $ext) {
        try {
            $lines = 0
            $sr = New-Object System.IO.StreamReader($Path, $true)
            try { while ($null -ne $sr.ReadLine()) { $lines++ } } finally { $sr.Dispose() }
            $enc = $null
            try { $enc = $sr.CurrentEncoding.WebName } catch {}
            if ($enc) { return ("Lines: {0}`r`nEncoding: {1}" -f $lines,$enc) }
            return ("Lines: {0}" -f $lines)
        } catch {}
    }

    if (@(".docx",".xlsx",".pptx") -contains $ext) {
        $core = Get-ZipXmlEntry -ZipPath $Path -EntryName "docProps/core.xml"
        $app  = Get-ZipXmlEntry -ZipPath $Path -EntryName "docProps/app.xml"
        $parts = @()
        try {
            if ($core) {
                [xml]$x = $core
                $title = $x.coreProperties.title
                $creator = $x.coreProperties.creator
                $last = $x.coreProperties.lastModifiedBy
                if ($title) { $parts += ("Title: {0}" -f $title) }
                if ($creator) { $parts += ("Author: {0}" -f $creator) }
                if ($last) { $parts += ("Last modified by: {0}" -f $last) }
            }
        } catch {}
        try {
            if ($app) {
                [xml]$a = $app
                $appname = $a.Properties.Application
                if ($appname) { $parts += ("Application: {0}" -f $appname) }
            }
        } catch {}
        if ((Get-Count $parts) -gt 0) { return ($parts -join "`r`n") }
    }

    if ($ext -eq ".pdf") {
        try {
            $fs = [System.IO.File]::OpenRead($Path)
            try {
                $buf = New-Object byte[] (200000)
                $n = $fs.Read($buf,0,$buf.Length)
                if ($n -gt 0) {
                    $txt = [System.Text.Encoding]::ASCII.GetString($buf,0,$n)
                    $title=$null; $author=$null
                    try { $m=[regex]::Match($txt,'/Title\s*\(([^)]{1,200})\)'); if ($m.Success) { $title=$m.Groups[1].Value } } catch {}
                    try { $m=[regex]::Match($txt,'/Author\s*\(([^)]{1,200})\)'); if ($m.Success) { $author=$m.Groups[1].Value } } catch {}
                    $parts=@()
                    if ($title) { $parts += ("Title: {0}" -f $title) }
                    if ($author) { $parts += ("Author: {0}" -f $author) }
                    if ((Get-Count $parts) -gt 0) { return ($parts -join "`r`n") }
                }
            } finally { $fs.Dispose() }
        } catch {}
    }

    return $null
}

$btnOpenFolder.Add_Click({ Do-OpenFolder })


$btnMove.Add_Click({ Do-MoveFiles })
$btnDescribe.Add_Click({ Do-Describe })

$btnDelete.Add_Click({ Do-DeleteFiles })



$btnCopyPath.Add_Click({ Do-CopyPath })

$btnBodyRename.Add_Click({ Do-BodyRename })

$btnAdd.Add_Click({ Do-AddTag })

$btnRemove.Add_Click({ Do-RemoveTag })

$btnCopyTags.Add_Click({ Do-CopyTags })




$btnDup.Add_Click({ Do-ToggleDuplicates })
$chkBody.Add_CheckedChanged({

    Update-FilterControls

    Run-SearchAndFillGrid -PreferredPaths @(Get-SelectedPaths) -FallbackIndex (Get-FirstSelectedIndex)

})

$chkTag.Add_CheckedChanged({

    Update-FilterControls

    Run-SearchAndFillGrid -PreferredPaths @(Get-SelectedPaths) -FallbackIndex (Get-FirstSelectedIndex)

})



# Tag choisi dans "Tags found" => ajoute au filtre Tag et relance

$comboFoundTags.Add_SelectionChangeCommitted({

    $t = [string]$comboFoundTags.SelectedItem

    if (-not [string]::IsNullOrWhiteSpace($t)) {

        if ([string]::IsNullOrWhiteSpace($txtTag.Text)) {

            $txtTag.Text = $t

        } else {

            $txtTag.Text = ($txtTag.Text.Trim() + " ou " + $t)

        }

        # Si le filtre Tag n'est pas actif, l'activer (la recherche se déclenchera via CheckedChanged)

        if (-not $chkTag.Checked) {

            $chkTag.Checked = $true

        } else {

            Run-SearchAndFillGrid -PreferredPaths @(Get-SelectedPaths) -FallbackIndex (Get-FirstSelectedIndex)

        }

    }

})



# Raccourcis clavier sur la grid

$grid.Add_KeyDown({

    param($sender,$e)




    # Esc interrupts an in-progress search
    try {
        elseif ($script:IsHashingDuplicates -and $script:DupWorker -and $script:DupWorker.IsBusy) {
            try { Cancel-DuplicateWorker } catch { }
            $e.SuppressKeyPress = $true
            $e.Handled = $true
            return
        }
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
            if ($script:IsSearching) {
                Request-InterruptSearch
                $e.SuppressKeyPress = $true
                $e.Handled = $true
                return
            }
        }
    } catch { }
    if     ($e.Control -and $e.KeyCode -eq "A") { $btnAdd.PerformClick();        $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "R") { $btnRemove.PerformClick();     $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "B") { $btnBodyRename.PerformClick(); $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "C") { $btnCopyPath.PerformClick();   $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "E") { $btnExecute.PerformClick();    $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "T") { $btnCopyTags.PerformClick();   $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "S") { $btnSearch.PerformClick();     $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "O") { $btnBrowse.PerformClick();     $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "F") { $btnOpenFolder.PerformClick();        $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "D") { $btnDescribe.PerformClick();          $e.SuppressKeyPress = $true }

    elseif ($e.Control -and $e.KeyCode -eq "L") { $btnDelete.PerformClick();            $e.SuppressKeyPress = $true }
    elseif ($e.Control -and $e.KeyCode -eq "H") { $btnHelp.PerformClick();      $e.SuppressKeyPress = $true }

    elseif ($e.KeyCode -eq "Enter") {

        if (Ensure-ExactlyOneSelected) {

            $p = @(Get-SelectedPaths)[0]

            if ($p) { Execute-Paths @($p) }

        }

        $e.SuppressKeyPress = $true

    }
        if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::M) { $btnMove.PerformClick(); $e.Handled=$true; return }
        if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::U) { $btnDup.PerformClick(); $e.Handled=$true; return }

})



# Double-clic => Execute

# Double-clic => Execute (comme Ctrl+E)

$grid.Add_CellDoubleClick({

    param($sender, $e)



    # Ignore header / divider double-clicks (RowIndex -1) so column auto-size works normally

    if ($null -ne $e -and $e.RowIndex -lt 0) { return }



    try {

        # S'assurer que la ligne double-cliquée devient la sélection (sinon SelectedRows peut être vide/ancienne)

        if ($null -ne $e -and $e.RowIndex -ge 0 -and $e.RowIndex -lt $grid.Rows.Count) {

            $grid.ClearSelection()

            $grid.Rows[$e.RowIndex].Selected = $true

            $grid.CurrentCell = $grid.Rows[$e.RowIndex].Cells[0]

        }



        # Même logique que Ctrl+E (qui fonctionne)

        if (Ensure-ExactlyOneSelected) {

            $p = @(Get-SelectedPaths)[0]

            if ($p) { Execute-Paths @($p) }

        }

    } catch {

        [System.Windows.Forms.MessageBox]::Show($form, "Cannot open:`r`n$($_.Exception.Message)", "Execute",

            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null

    }

})



# Resize => ajuste les colonnes

# ------------------------------ Startup / Shutdown ------------------------------






# ------------------------------ Run ------------------------------



[System.Windows.Forms.Application]::Run($form)


# ==================================================================================================