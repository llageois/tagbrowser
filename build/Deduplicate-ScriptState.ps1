#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Path = ".\tagsearch_v2.ps1",

    [Parameter(Mandatory = $false)]
    [switch]$EnableLogs
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding  = [System.Text.Encoding]::UTF8
} catch { }

function Write-AppLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($EnableLogs.IsPresent) {
        try { Write-Verbose -Message $Message -Verbose } catch { }
        try { Write-Information -MessageData $Message -InformationAction Continue } catch { }
    }
}

$fullPath = [System.IO.Path]::GetFullPath($Path)
if (-not (Test-Path -LiteralPath $fullPath)) {
    throw ("Fichier introuvable : {0}" -f $fullPath)
}

# Backup
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = $fullPath + ".bak_" + $ts
Copy-Item -LiteralPath $fullPath -Destination $backupPath -Force
Write-AppLog ("Backup créé : {0}" -f $backupPath)

# Lecture UTF-8 (tolère BOM)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$bytes = [System.IO.File]::ReadAllBytes($fullPath)
$text  = [System.Text.Encoding]::UTF8.GetString($bytes)

# Normaliser en LF pour traitement, puis on réécrit en CRLF
$text = $text -replace "`r`n|`r", "`n"
$lines = $text -split "`n", 0

# Match : $script:VarName = RHS   (RHS pris tel quel jusqu'à fin de ligne)
$rx = '^\s*\$script:(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<rhs>.+?)\s*$'

$seen = @{}               # name -> rhs string (normalized)
$removed = New-Object System.Collections.Generic.List[string]
$conflicts = New-Object System.Collections.Generic.List[string]

$out = New-Object System.Collections.Generic.List[string]

for ($i = 0; $i -lt $lines.Length; $i++) {
    $line = $lines[$i]

    $m = [regex]::Match($line, $rx)
    if (-not $m.Success) {
        [void]$out.Add($line)
        continue
    }

    $name = $m.Groups['name'].Value
    $rhs  = $m.Groups['rhs'].Value

    # Normalisation légère : espaces internes compressés
    $rhsNorm = ($rhs -replace '\s+', ' ').Trim()

    if (-not $seen.ContainsKey($name)) {
        $seen[$name] = $rhsNorm
        [void]$out.Add($line)
        continue
    }

    if ($seen[$name] -eq $rhsNorm) {
        [void]$removed.Add(("L{0}: {1} = {2}" -f ($i + 1), $name, $rhsNorm))
        continue
    }

    # Valeur différente : on conserve et on signale
    [void]$conflicts.Add(("L{0}: {1} déjà vu avec [{2}] puis [{3}]" -f ($i + 1), $name, $seen[$name], $rhsNorm))
    [void]$out.Add($line)
}

# Réécriture CRLF + fin de fichier
$result = ($out.ToArray() -join "`r`n")
if (-not $result.EndsWith("`r`n")) { $result += "`r`n" }

[System.IO.File]::WriteAllText($fullPath, $result, $utf8NoBom)

$reportPath = Join-Path (Split-Path -Parent $fullPath) ("dedup_script_state_report_{0}.txt" -f $ts)

$report = New-Object System.Collections.Generic.List[string]
$report.Add(("Fichier   : {0}" -f $fullPath))
$report.Add(("Backup    : {0}" -f $backupPath))
$report.Add(("Supprimés : {0}" -f $removed.Count))
$report.Add(("Conflits  : {0}" -f $conflicts.Count))
$report.Add("")
$report.Add("=== SUPPRIMÉS (doublons identiques) ===")
if ($removed.Count -eq 0) { $report.Add("(aucun)") } else { $report.AddRange($removed) }
$report.Add("")
$report.Add("=== CONFLITS (valeurs différentes, conservées) ===")
if ($conflicts.Count -eq 0) { $report.Add("(aucun)") } else { $report.AddRange($conflicts) }

[System.IO.File]::WriteAllText($reportPath, ($report -join "`r`n") + "`r`n", $utf8NoBom)

Write-Output ("OK. Doublons supprimés: {0}. Conflits conservés: {1}." -f $removed.Count, $conflicts.Count)
Write-Output ("Rapport: {0}" -f $reportPath)
