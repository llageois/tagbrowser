#Requires -Version 5.1
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$modulePath = Join-Path -Path $root -ChildPath 'src\TagBrowser.Core\TagBrowser.Core.psm1'

Describe 'TagBrowser.Core' {

    It 'Importe le module sans erreur' {
        { Import-Module -Name $modulePath -Force -ErrorAction Stop } | Should Not Throw
    }

    Context 'Normalize-Tags / Build-NewName' {

        BeforeEach {
            Import-Module -Name $modulePath -Force -ErrorAction Stop
        }

        It 'Normalise (lower+unique) et place cl/ps en tête' {
            $r = Normalize-Tags -Tags @('SWA', 'ps', 'Cl', 'abc', 'Abc')
            $r[0] | Should Be 'cl'
            $r[1] | Should Be 'ps'
            ($r -join ',') | Should Be 'cl,ps,abc,swa'
        }

        It 'Place les suffixes cim/cob/cif/swa en fin' {
            $r = Normalize-Tags -Tags @('zeta', 'xxcim', 'alpha', 'bbbSWA', 'ps')
            $r[0]  | Should Be 'ps'
            $r[-1] | Should Be 'xxcim'
        }

        It 'Construit le nom avec tags triés et séparés par + ' {
            $name = Build-NewName -Body 'Titre' -Tags @('b', 'a', 'ps') -Ext '.mp4'
            $name | Should Be 'Titre (ps + a + b).mp4'
        }

        It 'Construit le nom sans tags si liste vide' {
            $name = Build-NewName -Body 'Titre' -Tags @() -Ext '.txt'
            $name | Should Be 'Titre.txt'
        }

        It 'Gère les accents sans crash' {
            $s = Safe-TrimLower -Text 'Éléphant Çà va ?'
            $s | Should Be 'éléphant çà va ?'
        }
    }
}
