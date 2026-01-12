#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ""
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding  = [System.Text.Encoding]::UTF8
} catch { }

function Get-LatestReportPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Folder
    )

    $files = @(
        Get-ChildItem -LiteralPath $Folder -File -Filter "tag_logic_report_*.txt" -ErrorAction Stop |
            Sort-Object -Property LastWriteTime -Descending
    )

    if ($files.Count -eq 0) {
        throw "Aucun rapport trouvé (tag_logic_report_*.txt) dans le dossier."
    }

    return $files[0].FullName
}

$folder = Get-Location
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Get-LatestReportPath -Folder $folder.Path
}

$fullReportPath = [System.IO.Path]::GetFullPath($ReportPath)
if (-not (Test-Path -LiteralPath $fullReportPath)) {
    throw ("Rapport introuvable : {0}" -f $fullReportPath)
}

$raw = Get-Content -LiteralPath $fullReportPath -Raw
$raw = $raw -replace "`r`n|`r", "`n"
$lines = $raw -split "`n", 0

$rx = '^(?<cat>[^\t]+)\tL(?<ln>\d+)\t'
$groups = @{}  # cat -> list of ints

foreach ($l in $lines) {
    $m = [regex]::Match($l, $rx)
    if (-not $m.Success) { continue }

    $cat = $m.Groups['cat'].Value.Trim()
    $ln = [int]$m.Groups['ln'].Value

    if (-not $groups.ContainsKey($cat)) {
        $groups[$cat] = New-Object System.Collections.Generic.List[int]
    }

    $groups[$cat].Add($ln)
}

if ($groups.Count -eq 0) {
    throw "Aucune entrée analysable dans le rapport (format inattendu ?)."
}

$summary = New-Object System.Collections.Generic.List[string]
$summary.Add(("Rapport: {0}" -f $fullReportPath))
$summary.Add("")

foreach ($cat in ($groups.Keys | Sort-Object)) {
    $nums = @($groups[$cat] | Sort-Object)
    $count = $nums.Count
    $first = @($nums | Select-Object -First 10) -join ","
    $summary.Add(("{0} | {1} | {2}" -f $cat, $count, $first))
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$outPath = Join-Path (Split-Path -Parent $fullReportPath) ("tag_logic_summary_{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
[System.IO.File]::WriteAllText($outPath, ($summary -join "`r`n") + "`r`n", $utf8NoBom)

Write-Output ("OK. Résumé: {0}" -f $outPath)
