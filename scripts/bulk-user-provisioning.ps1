<#
.SYNOPSIS
    Bulk provisions Active Directory user accounts from a CSV file.

.DESCRIPTION
    Reads a CSV of new hires, creates their AD accounts in the specified OU,
    assigns them to their department security group, sets an initial password,
    and forces a password change at next logon.

.PARAMETER CsvPath
    Path to the CSV file containing user data.
    Required columns: FirstName, LastName, Department, Title, Manager

.PARAMETER DefaultOU
    Distinguished Name of the target OU for new accounts.
    Example: "OU=Staff,DC=kavtech,DC=com"

.PARAMETER DefaultPassword
    Initial password assigned to all new accounts.
    Users will be forced to change it at first logon.

.EXAMPLE
    .\bulk-user-provisioning.ps1 -CsvPath ".\new-hires.csv" -DefaultOU "OU=Staff,DC=kavtech,DC=com"

.NOTES
    Requires: ActiveDirectory module (RSAT), Domain Admin or Account Operator privileges
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [string]$CsvPath,

    [Parameter(Mandatory)]
    [string]$DefaultOU,

    [string]$DefaultPassword = "Welcome1!",

    [string]$Domain = "kavtech.com",

    [string]$LogPath = ".\provisioning-log.csv"
)

#region --- Setup ---
Import-Module ActiveDirectory -ErrorAction Stop

$securePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
$results        = [System.Collections.Generic.List[PSCustomObject]]::new()
$users          = Import-Csv -Path $CsvPath
$timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Starting bulk provisioning — $($users.Count) users to process`n" -ForegroundColor Cyan
#endregion

foreach ($user in $users) {

    $firstName   = $user.FirstName.Trim()
    $lastName    = $user.LastName.Trim()
    $department  = $user.Department.Trim()
    $title       = $user.Title.Trim()
    $manager     = $user.Manager.Trim()

    # Build standard username: first initial + last name, lowercase
    $samAccount  = ($firstName.Substring(0,1) + $lastName).ToLower() -replace '\s',''
    $upn         = "$samAccount@$Domain"
    $displayName = "$firstName $lastName"

    $result = [PSCustomObject]@{
        Timestamp   = $timestamp
        DisplayName = $displayName
        SamAccount  = $samAccount
        UPN         = $upn
        Department  = $department
        Title       = $title
        Status      = $null
        Notes       = $null
    }

    try {
        # Check for duplicate
        if (Get-ADUser -Filter "SamAccountName -eq '$samAccount'" -ErrorAction SilentlyContinue) {
            $result.Status = "SKIPPED"
            $result.Notes  = "Account already exists"
            Write-Warning "  [$samAccount] Already exists — skipping"
            $results.Add($result)
            continue
        }

        $newUserParams = @{
            SamAccountName        = $samAccount
            UserPrincipalName     = $upn
            GivenName             = $firstName
            Surname               = $lastName
            DisplayName           = $displayName
            Name                  = $displayName
            Department            = $department
            Title                 = $title
            AccountPassword       = $securePassword
            Enabled               = $true
            ChangePasswordAtLogon = $true
            Path                  = $DefaultOU
        }

        if ($PSCmdlet.ShouldProcess($samAccount, "Create AD user")) {
            New-ADUser @newUserParams

            # Assign to department security group if it exists
            $groupName = "GRP-$department"
            if (Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue) {
                Add-ADGroupMember -Identity $groupName -Members $samAccount
                $result.Notes = "Added to $groupName"
            } else {
                $result.Notes = "Group '$groupName' not found — group membership skipped"
            }

            $result.Status = "SUCCESS"
            Write-Host "  [OK] $displayName ($samAccount) provisioned" -ForegroundColor Green
        }

    } catch {
        $result.Status = "FAILED"
        $result.Notes  = $_.Exception.Message
        Write-Error "  [FAIL] $displayName ($samAccount): $($_.Exception.Message)"
    }

    $results.Add($result)
}

# Export log
$results | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8

$successCount = ($results | Where-Object Status -eq "SUCCESS").Count
$failCount    = ($results | Where-Object Status -eq "FAILED").Count
$skipCount    = ($results | Where-Object Status -eq "SKIPPED").Count

Write-Host "`n--- Provisioning Summary ---" -ForegroundColor Cyan
Write-Host "  Created : $successCount" -ForegroundColor Green
Write-Host "  Skipped : $skipCount"    -ForegroundColor Yellow
Write-Host "  Failed  : $failCount"    -ForegroundColor Red
Write-Host "  Log     : $LogPath`n"
