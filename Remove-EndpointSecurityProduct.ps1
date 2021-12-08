<#
    .SYNOPSIS
        Removes all copies of an endpoint security product that were installed via an MSI or an MSI wrapped
        in an EXE.

    .DESCRIPTION
        Removes all copies of an endpoint security product that were installed via an MSI or an MSI wrapped
        in an EXE. This includes removing the actual program, as well as any left over entries in Security
        Center.

        There are protections in place to prevent the uninstall of Windows Defender or the removal of its entry in
        Security Center, even if $Name would match it.

        This script only works on the desktop edition of PowerShell for Microsoft Windows, and must be run with
        local administrative rights.

    .EXAMPLE
        Remove-EndpointSecurityProduct.ps1 -Name '^(FortiClient|Symantec Endpoint Protection)$'

        Removes all copies of Symantec Endpoint Protection and FortiClient, including any left over entries in
        Security Center. Will automatically reboot the system if needed.

    .OUTPUTS
        System.Boolean

        Outputs $True if all operations were completed successfully, $False otherwise.

    .NOTES
        Author    : Dan Thompson
        Copyright : 2021 Case Western Reserve University
        Version   : 1.0.0
#>

#Requires -PSEdition Desktop
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]

param(
    # The name of the product to remove, as displayed in the list of installed programs or the Security Center.
    # This can be the exact name, or a regular expression.
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [Alias('np')]
    [string]$Name,

    # Skips uninstalling Symantec Endpoint Protection. Usually used if you have uninstalled SEP via other means
    # and just want to clean up the Security Center.
    [Alias('spu')]
    [switch]$SkipProductUninstall,

    # Skips removing entries left over in Security Center after an uninstall. These can prevent other AV products
    # from functioning properly.
    [Alias('sscc')]
    [switch]$SkipSecurityCenterCleanup,

    # Set this to not reboot if a reboot is needed.
    [Alias('sr')]
    [switch]$SkipReboot
)

$RebootNeeded = $False
$Success = $True

$ProductRegistryKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
if ([System.Environment]::Is64BitOperatingSystem) {
    $ProductRegistryKeys += 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
}

0 | Set-Variable -Name 'ERROR_SUCCESS' -Option 'Constant' -WhatIf:$False
1641 | Set-Variable -Name 'ERROR_SUCCESS_REBOOT_INITIATED' -Option 'Constant' -WhatIf:$False
3010 | Set-Variable -Name 'ERROR_SUCCESS_REBOOT_REQUIRED' -Option 'Constant' -WhatIf:$False

@(
    $ERROR_SUCCESS,
    $ERROR_SUCCESS_REBOOT_INITIATED,
    $ERROR_SUCCESS_REBOOT_REQUIRED
) | Set-Variable -Name 'SUCCESS_CODES' -Option 'Constant' -WhatIf:$False

@(
    $ERROR_SUCCESS_REBOOT_INITIATED,
    $ERROR_SUCCESS_REBOOT_REQUIRED
) | Set-Variable -Name 'SUCCESS_REBOOT_CODES' -Option 'Constant' -WhatIf:$False

if ($SkipProductUninstall.IsPresent) {
    Write-Verbose -Message "Skipping uninstalling products matching ""$Name"" per user preference."
} else {
    $UninstallPercentComplete = 0
    $UninstallProgressParams = @{
        'Activity' = "Uninstalling products with name matching ""$Name"" ..."
        'CurrentOperation' = 'Looking for copies'
        'Status' = "$UninstallPercentComplete% Complete"
    }

    Write-Progress @UninstallProgressParams

    $Copies = $ProductRegistryKeys | Get-ItemProperty | Where-Object {
        $_.UninstallString -match '^msiexec' -and
        $_.DisplayName -match $Name -and
        $_.DisplayName -notmatch 'Windows Defender'
    }

    $NumCopies = ($Copies | Measure-Object).Count

    if (0 -eq $NumCopies) {
        Write-Warning -Message "No copies matching ""$Name"" found. Nothing to uninstall!"
    } else {
        Write-Verbose -Message "$NumCopies copies matching ""$Name"" found."

        $Copies | ForEach-Object {
            $CopyMessageSuffix = "copy of ""$($_.DisplayName)"" with GUID $($_.PSChildName)."

            $UninstallProgressParams.CurrentOperation = "Uninstalling $CopyMessageSuffix"
            Write-Progress @UninstallProgressParams

            $MsiexecArgs = @(
                '/x',
                $_.PSChildName,
                '/qb',
                '/norestart',
                'REBOOT=ReallySuppress',
                'MSIRESTARTMANAGERCONTROL=Disable'
            )

            # Symantec Endpoint Protection uses its own additional proprietary switch to suppress reboots.
            if ('Symantec Endpoint Protection' -eq $_.DisplayName) {
                $MsiexecArgs += 'SYMREBOOT=ReallySuppress'
            }

            if ($PSCmdlet.ShouldProcess("msiexec $($MsiexecArgs -join ' ')", 'Start-Process')) {
                $UninstallProcessParams = @{
                    'FilePath' = 'msiexec'
                    'ArgumentList' = $MsiexecArgs
                    'Wait' = $True
                    'PassThru' = $True
                }
                $UninstallProcess = Start-Process @UninstallProcessParams

                if ($SUCCESS_CODES -contains $UninstallProcess.ExitCode) {
                    Write-Verbose -Message "Successfully uninstalled $CopyMessageSuffix."
                    $RebootNeeded = $SUCCESS_REBOOT_CODES -contains $UninstallProcess.ExitCode
                } else {
                    Write-Error -Message "Failed to uninstall $CopyMessageSuffix."
                    $Success = $False
                }
            }

            $UninstallPercentComplete += (1 / $NumCopies) * 100
            $UninstallProgressParams.Status = "$($UninstallPercentComplete.ToString('#'))% Complete"
        }
    }
}

if ($SkipSecurityCenterCleanup.IsPresent) {
    Write-Verbose -Message 'Skipping Security Center cleanup per user preference.'
} else {
    $SCPercentComplete = 0
    $SCProgressParams = @{
        'Activity' = "Removing leftover entries with displayName like ""$NamePattern"" ..."
        'CurrentOperation' = 'Looking for entries'
        'Status' = "$SCPercentComplete% Complete"
    }

    Write-Progress @SCProgressParams

    $SCGetWmiParams = @{
        'Class' = 'AntiVirusProduct'
        'Namespace' = 'root\SecurityCenter2'
    }

    $SCEntries = Get-WmiObject @SCGetWmiParams | Where-Object {
        $_.DisplayName -match $Name -and
        $_.DisplayName -notmatch 'Windows Defender'
    }

    $NumSCEntries = ($SCEntries | Measure-Object).Count

    Write-Verbose -Message "$NumSCEntries leftover entries found in Security Center."
    
    if ($SCEntries) {
        $SCEntries | ForEach-Object {
            $SCMessageSuffix = "entry named ""$($_.DisplayName)"" with instance GUID $($_.InstanceGuid)."

            $SCProgressParams.CurrentOperation = "Removing $SCMessageSuffix"
            Write-Progress @SCProgressParams

            
            if ($PSCmdlet.ShouldProcess($_.InstanceGuid, 'Remove-WmiObject')) {
                $SCRemoveEntryJob = $_ | Remove-WmiObject -AsJob
                $SCRemoveEntryJob | Receive-Job -Wait -AutoRemoveJob | Out-Null

                if ('Completed' -eq $SCRemoveEntryJob.State) {
                    Write-Verbose -Message "Successfully removed $SCMessageSuffix"
                } else {
                    Write-Error -Message "Failed to remove $SCMessageSuffix"
                    $Success = $False
                }
            }

            $SCPercentComplete += (1 / $NumSCEntries) * 100
            $SCProgressParams.Status = "$($SCPercentComplete.ToString('#'))% Complete"
        }
    }
}

$Success

if ($RebootNeeded) {
    if ($SkipReboot.IsPresent) {
        Write-Warning -Message 'Reboot required, but skipping per user preferences.'
    } else {
        Write-Verbose -Message 'Reboot required. Rebooting.'
        Restart-Computer
    }
} else {
    Write-Verbose -Message 'No reboot required.'
}
