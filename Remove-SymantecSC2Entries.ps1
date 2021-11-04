<#
    .SYNOPSIS
        Removes entries left over in Security Center 2 after Symantec antivirus products are uninstalled.

    .DESCRIPTION
        Removes entries left over in Security Center 2 after Symantec antivirus products are uninstalled.

        This script only works on the desktop edition of PowerShell for Microsoft Windows.

    .NOTES
        Author    : Dan Thompson
        Copyright : 2021 Case Western Reserve University
        Version   : 1.0.0
#>

#Requires -PSEdition Desktop
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]

param()

begin {
    $GetWmiParams = @{
        Class = 'AntiVirusProduct'
        Namespace = 'root\SecurityCenter2'
        Filter = 'displayName LIKE "Symantec%" OR displayName LIKE "Norton%"'
    }

    $RemoveWmiParams = @{
        Debug = $DebugPreference
        Verbose = $VerbosePreference
        WhatIf = $WhatIfPreference
    }
}

process {
    $Entries = Get-WmiObject @GetWmiParams
    $NumberOfEntries = ($Entries | Measure-Object).Count

    if ($NumberOfEntries -gt 0) {
        Write-Verbose -Message "Found $NumberOfEntries entries. Attempting to remove ..."
        $Entries | Remove-WmiObject @RemoveWmiParams
    } else {
        Write-Warning -Message 'No entries found! Nothing to do.'
    }
}
