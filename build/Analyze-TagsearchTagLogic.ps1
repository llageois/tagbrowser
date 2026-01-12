#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Path = ".\tagsearch_v2.ps1"
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding  = [System.Text.Encoding]::UTF8
} catch { }

$fullPath = [System.IO.Path]::GetFullPath($Path)
if (-not (Test-Path -LiteralPath $fullPath)) {
    throw ("Fichier introuvable : {0}" -f $fullPath)
}

# Lecture texte
$text = Get-Content -LiteralPath $fullPath -Raw
$text = $text -replace "`r`n|`r", "`n"
$lines = $text -split "`n", 0

# Patterns “forts” liés aux tags + règles connues (cl/ps et suffixes)
$patterns = @(
    @{ Name = "Tags: cl/ps";           Rx = "(?i)\b(cl|ps)\b" },
    @{ Name = "Suffixes: cim/cob/cif/swa"; Rx = "(?i)\b(cim|cob|cif|swa)\b" },
    @{ Name = "Join plus";             Rx = "\s\+\s" },
    @{ Name = "Parentheses tags";      Rx = "\([^\)]*\+[^\)]*\)" },
    @{ Name = "Split separators";      Rx = "(?i)\b-split\b|Split\(" },
    @{ Name = "Replace tags";          Rx = "(?i)\b-replace\b|Replace\(" },
    @{ Name = "Regex tags";            Rx = "(?i)\[regex\]::|Regex\(" }
)

$hits = New-Object System.Collections.Generic.List[string]

foreach ($p in $patterns) {
    $rx = [regex]::new($p.Rx)
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($rx.IsMatch($lines[$i])) {
            $hits.Add(("{0}`tL{1}`t{2}" -f $p.Name, ($i + 1), ($lines[$i].Trim())))
        }
    }
}

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = Join-Path (Split-Path -Parent $fullPath) ("tag_logic_report_{0}.txt" -f $ts)

$header = @(
    ("Fichier : {0}" -f $fullPath),
    ("Lignes  : {0}" -f $lines.Length),
    ("Hits    : {0}" -f $hits.Count),
    "",
    "Format: <Catégorie><TAB>L<ligne><TAB><ligne (trim)>",
    ""
)

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($reportPath, (($header + $hits) -join "`r`n") + "`r`n", $utf8NoBom)

Write-Output ("OK. Rapport: {0}" -f $reportPath)
Write-Output ("Total hits: {0}" -f $hits.Count)
