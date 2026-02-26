<#
.SYNOPSIS
    Audits Active Directory user accounts and generates an access report.

.DESCRIPTION
    Enumerates all AD users, collects group memberships, last logon timestamps,
    account status, and password age. Flags stale accounts (no logon in X days)
    and accounts with passwords that never expire. Exports a CSV report.

.PARAMETER ExportPath
    Path for the output CSV report.

.PARAMETER StaleThresholdDays
    Number of days without logon before an account is flagged as stale.
    Default: 90

.PARAMETER SearchBase
    OU to scope the audit. Defaults to the entire domain.

.EXAMPLE
    .\access-audit.ps1 -ExportPath ".\audit-report.csv"

.EXAMPLE
    .\access-audit.ps1 -ExportPath ".\audit-report.csv" -StaleThresholdDays 60 -SearchBase "OU=Staff,DC=kavtech,DC=com"

.NOTES
    Requires: ActiveDirectory module (RSAT), read access to AD
#>

[CmdletBinding()]
param (
    [string]$ExportPath         = ".\access-audit-$(Get-Date -Format 'yyyyMMdd').csv",
    [int]$StaleThresholdDays    = 90,
    [string]$SearchBase         = $null
)

Import-Module ActiveDirectory -ErrorAction Stop

$staleDate = (Get-Date).AddDays(-$StaleThresholdDays)
$report    = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] Starting access audit (stale threshold: $StaleThresholdDays days)`n" -ForegroundColor Cyan

$adParams = @{
    Filter     = "*"
    Properties = @(
        "DisplayName", "SamAccountName", "UserPrincipalName",
        "Department", "Title", "Manager",
        "Enabled", "LockedOut",
        "LastLogonDate", "PasswordLastSet", "PasswordNeverExpires",
        "PasswordExpired", "MemberOf",
        "Created", "Modified", "Description"
    )
}

if ($SearchBase) { $adParams["SearchBase"] = $SearchBase }

$users = Get-ADUser @adParams

Write-Host "  Found $($users.Count) accounts to audit...`n"

foreach ($user in $users) {

    # Resolve manager display name
    $managerName = $null
    if ($user.Manager) {
        try { $managerName = (Get-ADUser $user.Manager).Name } catch {}
    }

    # Flatten group memberships
    $groups = ($user.MemberOf | ForEach-Object {
        ($_ -split ',')[0] -replace '^CN=', ''
    }) -join "; "

    # Determine stale status
    $isStale = $false
    if ($null -eq $user.LastLogonDate -or $user.LastLogonDate -lt $staleDate) {
        $isStale = $true
    }

    # Password age in days
    $passwordAgeDays = $null
    if ($user.PasswordLastSet) {
        $passwordAgeDays = ((Get-Date) - $user.PasswordLastSet).Days
    }

    # Risk flags
    $flags = [System.Collections.Generic.List[string]]::new()
    if ($isStale -and $user.Enabled)              { $flags.Add("STALE_ACTIVE") }
    if ($user.PasswordNeverExpires)               { $flags.Add("PWD_NEVER_EXPIRES") }
    if ($user.PasswordExpired)                    { $flags.Add("PWD_EXPIRED") }
    if ($user.LockedOut)                          { $flags.Add("LOCKED_OUT") }
    if (-not $user.Enabled -and $user.MemberOf.Count -gt 1) { $flags.Add("DISABLED_HAS_GROUPS") }

    $report.Add([PSCustomObject]@{
        DisplayName          = $user.DisplayName
        SamAccountName       = $user.SamAccountName
        UPN                  = $user.UserPrincipalName
        Department           = $user.Department
        Title                = $user.Title
        Manager              = $managerName
        Enabled              = $user.Enabled
        LockedOut            = $user.LockedOut
        LastLogonDate        = $user.LastLogonDate
        DaysSinceLogon       = if ($user.LastLogonDate) { ((Get-Date) - $user.LastLogonDate).Days } else { "Never" }
        IsStale              = $isStale
        PasswordLastSet      = $user.PasswordLastSet
        PasswordAgeDays      = $passwordAgeDays
        PasswordNeverExpires = $user.PasswordNeverExpires
        PasswordExpired      = $user.PasswordExpired
        GroupMemberships     = $groups
        GroupCount           = $user.MemberOf.Count
        AccountCreated       = $user.Created
        RiskFlags            = ($flags -join ", ")
    })
}

$report | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

# Summary stats
$enabled      = ($report | Where-Object Enabled -eq $true).Count
$disabled     = ($report | Where-Object Enabled -eq $false).Count
$staleActive  = ($report | Where-Object { $_.IsStale -eq $true -and $_.Enabled -eq $true }).Count
$lockedOut    = ($report | Where-Object LockedOut -eq $true).Count
$pwdNoExpire  = ($report | Where-Object PasswordNeverExpires -eq $true).Count
$flagged      = ($report | Where-Object { $_.RiskFlags -ne "" }).Count

Write-Host "--- Audit Summary ---" -ForegroundColor Cyan
Write-Host "  Total accounts     : $($report.Count)"
Write-Host "  Enabled            : $enabled"     -ForegroundColor Green
Write-Host "  Disabled           : $disabled"    -ForegroundColor Yellow
Write-Host "  Stale & active     : $staleActive" -ForegroundColor Red
Write-Host "  Locked out         : $lockedOut"   -ForegroundColor Red
Write-Host "  Password never exp : $pwdNoExpire" -ForegroundColor Yellow
Write-Host "  Total flagged      : $flagged"     -ForegroundColor Red
Write-Host "`n  Report exported to : $ExportPath`n"
