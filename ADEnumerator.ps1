param (
    [string]$SamAccountName,
    [switch]$h
)
try {
    if (Get-Module PowerView){
        Remove-Module PowerView
    }
    Import-Module .\PowerView.ps1 -ErrorAction Stop
} catch {
    Write-Error "Failed to import the PowerView module: $_"
    Remove-Module PowerView
    exit    
}
if ($SamAccountName -and $h)
{
    Write-Error "Invalid Use of Parameters"
    exit
}
if ($h)
{
    Write-Host @"
    NAME
    ADEnumerator.ps1 - Custom PowerShell script designed to automate the enumeration of AD infrastructure by using PowerView.

    SYNOPSIS
        ADEnumerator.ps1 [-SamAccountName <String>]

    DESCRIPTION
        This script enumerates various Active Directory details including the current domain, domain controllers,
        OUs (Organizational Units), GPOs (Group Policy Objects) and their associated OUs, computers, users,
        unconstrained/constrained/RBCD (Resource-Based Constrained Delegation) computers and users,
        ASREP roasting users, kerberoastable users, and interesting ACLs.

    PARAMETERS
        -SamAccountName <String>
            Specify the SAM account name of a user or computer to retrieve additional details such as the groups it 
            belongs to, whether it is allowed to delegate, if it is kerberoastable or ASREP roastable, the associated ACLs
            and the derived ACLs from the groups it belongs to.

    EXAMPLES
        .\ADEnumerator.ps1
            - Enumerates Active Directory details for the current domain.

        .\ADEnumerator.ps1 -SamAccountName "username"
            - Retrieves additional details for the specified user.

        .\ADEnumerator.ps1 -SamAccountName "computername"
            - Retrieves additional details for the specified computer.

    OUTPUT
        The script outputs various details about the Active Directory environment including domain information, domain controllers,
        OUs, GPOs, computers, users, delegation status, kerberoasting status, and ACLs.

    NOTES
        Author: Ismail Barrous
        Date: 5-20-2024
        Version: 1.0
"@
exit
}
function Print_Banner{
    $banner = @"
          _____  ______                                      _             
    /\   |  __ \|  ____|                                    | |            
   /  \  | |  | | |__   _ __  _   _ _ __ ___   ___ _ __ __ _| |_ ___  _ __ 
  / /\ \ | |  | |  __| | '_ \| | | | '_ ` _  \ /  _\ '__/ _`  | __/ _ \| '__|
 / ____ \| |__| | |____| | | | |_| | | | | | |  __/ | | (_| | || (_) | |   
/_/    \_\_____/|______|_| |_|\__,_|_| |_| |_|\___|_|  \__,_|\__\___/|_|   

                                    by $( [char]27 )[1;31mIsmail Barrous$( [char]27 )[0m
                                    Version: $( [char]27 )[1;31m1.0$( [char]27 )[0m


"@
    Write-Host "$banner"
}
function Print_ACLs {
    param(
        [string]$ResultType,
        [array]$ACLs
    )
    Write-Host "`n$( [char]27 )[1m$ResultType : $( [char]27 )[0m"
    if ($ACLs) {
        $parsedResults = @()
        foreach ($ACE in $ACLs) {
            $ObjectName=($ACE.ObjectDN -split ',' | Select-Object -First 1 | ForEach-Object {($_ -split '=')[1]})
            $Rights=$($ACE.ActiveDirectoryRights) -split ', '
            $IdentityName = $($ACE.IdentityReferenceName)
            if (!$IdentityName)
            {
                $IdentityName = Convert-SidToName $ACE.SecurityIdentifier
            }
            foreach($Right in $Rights){
                $parsedResults += [PSCustomObject]@{
                    Object = $IdentityName
                    'ACE Type' = $Right
                    'Applied On' = $ObjectName
                }
            }
        }
        # Format results into a table
        $table = $parsedResults | Format-Table -Property Object, 'ACE Type', 'Applied On' -AutoSize
    
        # Convert the table to a string with tabulations
        $tableString = $table | Out-String
        $tableString = $tableString -replace "(?m)^", "  "
    
        # Output the formatted table string
        Write-Host $tableString
    } else {
        Write-Host "  No results were found." -ForegroundColor Red
    } 
}
function  ShowAcls {
    param(
        [array]$Entity
    )
    #Write-Host "$($Entity.SamAccountName) $($Entity.objectsid)"
    $DirectACLs = $InterestingACLs | ?{$_.SecurityIdentifier -like $Entity.objectsid}
    Print_ACLs -ACLs $DirectACLs
    Write-Host
}

function Print_Results {
    param(
        [string]$ResultType,
        [array]$Results
    )
    Write-Host "`n$( [char]27 )[1m$ResultType : $( [char]27 )[0m"
    if ($Results) { 
        foreach ($Result in $Results)
        {
            if ($Result.sAMAccountName) {
                Write-Host "  $($Result.sAMAccountName)" -ForegroundColor Green
            } elseif ($Result.Name) {
                Write-Host "  $($Result.Name)" -ForegroundColor Green
	    }
        }
    } else {
        Write-Host "  No results were found." -ForegroundColor Red
    }
}
function Print_Kerberoastable_Results {
    param(
        [string]$ResultType,
        [array]$Results
    )
    Write-Host "`n$( [char]27 )[1m$ResultType : $( [char]27 )[0m"
    if ($Results) { 
        $parsedResults = @()
        foreach ($Result in $Results)
        {
            $parsedResults += [PSCustomObject]@{
                SamAccountName = $Result.samaccountname
                SPN = $Result.serviceprincipalname
            }
        }
        $table = $parsedResults | Format-Table -Property SamAccountName, SPN -AutoSize
        $tableString = $table | Out-String
        $tableString = $tableString -replace "(?m)^", "  "
        Write-Host $tableString
    } else {
        Write-Host "  No results were found." -ForegroundColor Red
    }
}
function Print_Delegations {
    param (
        [string]$Delegations
    )
    $parsedResults = @()
    $Delegations_Array = ($Delegations -split ' ')
    foreach ($delegation in $Delegations_Array) {
        $allowedService = ($delegation -split '/')[0]
        $targetedComputer = ($delegation -split '/', 2)[1]
        $parsedResults += [PSCustomObject]@{
            AllowedService = $allowedService
            TargetedComputer = $targetedComputer
        }
    }
    $table = $parsedResults | Format-Table -Property AllowedService, TargetedComputer -AutoSize
    $tableString = $table | Out-String
    $tableString = $tableString -replace "(?m)^", "  "
    Write-Host $tableString
}


function Print_Constrained_Results {
    param(
        [string]$ResultType,
        [array]$Results
    )
    Write-Host "`n$( [char]27 )[1m$ResultType : $( [char]27 )[0m"
    if ($Results) { 
        foreach ($Result in $Results)
        {
            [System.DirectoryServices.ResultPropertyValueCollection] $allowedDelegations = $Result.'msds-allowedtodelegateto'
            if ($Result.sAMAccountName) {
                Write-Host "`n  $($Result.sAMAccountName) :" -ForegroundColor Green
                Print_Delegations -Delegations $allowedDelegations
            } elseif ($Result.Name) {
                Write-Host "`n  $($Result.Name)" -ForegroundColor Green
                Print_Delegations -Delegations $allowedDelegations
            }
        }
    } else {
        Write-Host "  No results were found." -ForegroundColor Red
    }
}

function Print_RBCD_Results {
    param(
        [array]$Results
    )
    Write-Host "`n$( [char]27 )[1mResource Based Constrained Delegation (RBCD) : $( [char]27 )[0m"
    if ($Results) { 
        foreach ($Result in $Results)
        {
            Write-Host -NoNewline "`n  $($Result.SourceName) " -ForegroundColor Green
            Write-Host -NoNewline "Allows "
            Write-Host -NoNewline "$($Result.DelegatedName) " -ForegroundColor Green
            Write-Host "to access its resources."
        }
    } else {
        Write-Host "  No results were found." -ForegroundColor Red
    }
}
function Print_GPO_Results {
    param(
        [array]$Results
    )
    Write-Host "`n$( [char]27 )[1mGroup Policy Objects (GPOs) : $( [char]27 )[0m"
    if ($Results) { 
        foreach ($Result in $Results)
        {
            $GPOName = $Result.cn -replace '}', ''
            $GPOName = $GPOName -replace '{', ''
            Write-Host "`n  [ * ] $GPOName" -ForegroundColor Green
            $AppliedOnOUs = $OUs | ?{$_.gplink -match $GPOName}
            if ($AppliedOnOUs)
            {
                Write-Host "  |" -ForegroundColor Green
                Write-Host "  └───────>" -ForegroundColor Green -NoNewline
                Write-Host " Applied On The Following OUs:"
                foreach ($AppliedOnOU in $AppliedOnOUs)
                {
                    Write-Host "            |" -ForegroundColor Yellow
                    Write-Host "            └───────> $($AppliedOnOU.name)" -ForegroundColor Yellow
                }
            }
        }
    } else {
        Write-Host "  No results were found." -ForegroundColor Red
    }
}

if ($SamAccountName)
{
    $User = Get-DomainUser $SamAccountName
    if ($User)
    {
        Print_Banner
        
        Write-Host "`n$( [char]27 )[1mIs $SamAccountName Trusted For Unconstrained Delegation ?$( [char]27 )[0m"
        
        if ($User.TrustedForDelegation -eq $true) {
            Write-Host "  True" -ForegroundColor Green
        }
        else {
            Write-Host "  False" -ForegroundColor Red            
        }

        if ($User."msDS-AllowedToDelegateTo") {
            Print_Constrained_Results "`nIs $SamAccountName Trusted For Constrained Delegation ?" @($User)
        }
        else {
            Write-Host "`n$( [char]27 )[1mIs $SamAccountName Trusted For Constrained Delegation ?$( [char]27 )[0m"
            Write-Host "  False" -ForegroundColor Red            
        }
        if ($User.ServicePrincipalName)
        {
            Print_Kerberoastable_Results "`nIs $SamAccountName Kerberoastable ?" @($User)
        }
        else {
            Write-Host "`n$( [char]27 )[1mIs $SamAccountName Kerberoastable ?$( [char]27 )[0m"
            Write-Host "  False" -ForegroundColor Red 
        }

        Write-Host "`n$( [char]27 )[1mIs $SamAccountName Vulnerable to AS-REP Roasting ?$( [char]27 )[0m"
        
        if ($User.useraccountcontrol -match "DONT_REQ_PREAUTH") {
            Write-Host "  True" -ForegroundColor Green
        }
        else {
            Write-Host "  False" -ForegroundColor Red            
        }

        $Groups = Get-DomainGroup -UserName $User.SamAccountName
        Print_Results "Joined Groups" $Groups
        $ACLs = Get-DomainObjectAcl
        $UserAcls = $ACLs | ?{$_.SecurityIdentifier -like $User.objectsid}
        $DerivatedAcls = @()
        Print_ACLs "Intresting ACLs" $UserAcls
        foreach($Group in $Groups)
        {
            $GroupAcls = $ACLs | ?{$_.SecurityIdentifier -like $Group.objectsid}
            $DerivatedAcls += $GroupAcls
        }
        Print_ACLs "Derivated ACLs" $DerivatedAcls        
    }else{
        Write-Host "Invalid SamAccountName." -ForegroundColor Red
    }
}
else {
    Print_Banner
    $Domains = Get-Domain
    $Users = Get-DomainUser
    $ASREPUsers = Get-DomainUser -PreauthNotRequired
    $KerberoastableUsers = Get-DomainUser -SPN
    $Groups = Get-DomainGroup
    $Computers = Get-DomainComputer
    $DomainControllers = Get-DomainController
    $OUs = Get-DomainOU
    $GPOs = Get-DomainGPO
    $UnConstrainedComputers = Get-DomainComputer -UnConstrained
    $UnConstrainedUsers = Get-DomainUser -UnConstrained
    $ConstrainedUsers = Get-DomainUser -TrustedToAuth
    $ConstrainedComputers = Get-DomainComputer -TrustedToAuth
    $RBCD = Get-DomainRBCD
    $InterestingACLs = Find-InterestingDomainAcl

    Print_Results "Domains" $Domains

    Print_Results "Domain Controllers" $DomainControllers

    Print_Results "Organizational Units" $OUs

    Print_GPO_Results $GPOs

    Print_Results "Computers" $Computers

    Print_Results "Computers Trusted for UnConstrained Delegation" $UnConstrainedComputers

    Print_Results "Users Trusted for UnConstrained Delegation" $UnConstrainedUsers

    Print_Constrained_Results "Computers Trusted for Constrained Delegation" $ConstrainedComputers

    Print_Constrained_Results "Users Trusted for Constrained Delegation" $ConstrainedUsers

    Print_RBCD_Results $RBCD

    Print_Results "Groups" $Groups

    Print_Results "Users" $Users

    Print_Results "Vulnerable Users to AS-REP Roasting" $ASREPUsers

    Print_Kerberoastable_Results "Vulnerable Users to Kerberoasting" $KerberoastableUsers

    Print_ACLs "Interesting ACLs" $InterestingACLs
}