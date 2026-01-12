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

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = $fullPath + ".bak_" + $ts
Copy-Item -LiteralPath $fullPath -Destination $backupPath -Force
Write-AppLog ("Backup : {0}" -f $backupPath)

# Lecture (tolère BOM)
$bytes = [System.IO.File]::ReadAllBytes($fullPath)
$text  = [System.Text.Encoding]::UTF8.GetString($bytes)
$text  = $text -replace "`r`n|`r", "`n"

$markerStart = "# region TagBrowser.Core"
$markerEnd   = "# endregion TagBrowser.Core"

if ($text -match [regex]::Escape($markerStart)) {
    Write-Output "OK: bloc TagBrowser.Core déjà présent (aucune modification)."
    return
}

$insertBlock = @"
$markerStart
`$script:tagBrowserCoreModulePath = Join-Path -Path `$PSScriptRoot -ChildPath 'src\TagBrowser.Core\TagBrowser.Core.psm1'
Import-Module -Name `$script:tagBrowserCoreModulePath -Force -ErrorAction Stop
$markerEnd

"@

# Insertion après un éventuel #Requires en tête, sinon au début
$lines = $text -split "`n", 0
$insertIndex = 0
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match '^\s*#Requires\b') {
        $insertIndex = $i + 1
        continue
    }
    break
}

$newLines = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($i -eq $insertIndex) {
        foreach ($bl in ($insertBlock -replace "`r","" -split "`n", 0)) {
            [void]$newLines.Add($bl)
        }
    }
    [void]$newLines.Add($lines[$i])
}

$result = ($newLines.ToArray() -join "`r`n")
if (-not $result.EndsWith("`r`n")) { $result += "`r`n" }

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($fullPath, $result, $utf8NoBom)

Write-Output "OK: bloc TagBrowser.Core inséré."
Write-Output ("Backup: {0}" -f $backupPath)
