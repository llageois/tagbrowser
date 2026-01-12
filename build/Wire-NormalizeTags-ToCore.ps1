#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetPath = ".\tagsearch_v2.ps1",

    [Parameter(Mandatory = $false)]
    [switch]$EnableLogs
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

function Write-AppLog {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Message)

    if ($EnableLogs.IsPresent) {
        try { Write-Verbose -Message $Message -Verbose } catch { }
        try { Write-Information -MessageData $Message -InformationAction Continue } catch { }
    }
}

$fullPath = [System.IO.Path]::GetFullPath($TargetPath)
if (-not (Test-Path -LiteralPath $fullPath)) {
    throw ("Fichier introuvable : {0}" -f $fullPath)
}

# Backup
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = $fullPath + ".bak_" + $ts
Copy-Item -LiteralPath $fullPath -Destination $backupPath -Force
Write-AppLog ("Backup : {0}" -f $backupPath)

# Lecture (UTF-8 tolérant BOM)
$bytes = [System.IO.File]::ReadAllBytes($fullPath)
$text  = [System.Text.Encoding]::UTF8.GetString($bytes)
$text  = $text -replace "`r`n|`r", "`n"

# Détecter si on a déjà câblé le wrapper
if ($text -match '#\s*region\s+Wire\s+Normalize-Tags\s+to\s+TagBrowser\.Core') {
    Write-Output "OK: wrapper déjà présent (aucune modification)."
    return
}

# Cherche une fonction Normalize-Tags existante dans le script
# Remplacement conservateur : on remplace le bloc complet "function Normalize-Tags { ... }"
$rx = '(?ms)^\s*function\s+Normalize-Tags\s*\{.*?^\s*\}\s*$'
$m = [regex]::Match($text, $rx)

if (-not $m.Success) {
    Write-Output "INFO: aucune fonction 'Normalize-Tags' trouvée dans tagsearch_v2.ps1 (aucune modification)."
    return
}

$wrapper = @"
# region Wire Normalize-Tags to TagBrowser.Core
function Normalize-Tags {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = `$false)]
        [string[]]`$Tags
    )

    # Appel explicite au module (évite la récursivité)
    return (TagBrowser.Core\Normalize-Tags -Tags `$Tags)
}
# endregion Wire Normalize-Tags to TagBrowser.Core
"@

$newText = $text.Substring(0, $m.Index) + $wrapper + $text.Substring($m.Index + $m.Length)

# Réécriture CRLF + fin de fichier
$result = $newText -replace "`n", "`r`n"
if (-not $result.EndsWith("`r`n")) { $result += "`r`n" }

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($fullPath, $result, $utf8NoBom)

Write-Output "OK: Normalize-Tags câblé vers TagBrowser.Core."
Write-Output ("Backup: {0}" -f $backupPath)
