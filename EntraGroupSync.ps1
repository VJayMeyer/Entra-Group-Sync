#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Groups, ActiveDirectory, Microsoft.PowerShell.Management
<#
    .SYNOPSIS
        This tool keeps AD and Entra Groups in sync.
        It does this by using a regex match to make sure Entra ID and AD 
            have a copy of the relevant group and the membership is consistent.
    .NOTES
        Limitations that led to this solution:
        - Entra Connect Sync Group Writeback V2 is deprecated as of 2.3.2.0
        - Entra Cloud Sync can only sync Universal Groups and has 
            no sync rules which can be edited.
        - Both mechanisms have 15 and 20 minute polling cycles.
        - Neither mechanism offers a way to notify the requester when AD and
            Entra are consistent.

        Developer notes:
        - Right now this is configured to handle Entra to AD but has been
            wired to support bi-directional support in the future.
        - Every effort has been taken to introduce robust error checking
            and cut down on service calls.
        - Tested with up to 250 managed priv groups in less than 60 seconds
            but can scale to 1000's. Just respect Graph rate limits.
        - This version will create the AD group but won't perform any further
           updates if the entra name or description changes.
        
        Security notes:
        - Minimum is Graph Group/GroupMember/User/Mail.Send and AD Group Member update.
            That will not provision or deprovision any groups but keep groups you
             manually create in sync.
        - Run this under a non-local admin gMSA.
        - Use a non-exportable private key to auth to Entra / Graph.
        - Use a ApplicationAccessPolicy in exchange to limit Graph Mail.send.
        - Use a new OU and fine grained AD permissions.
        - Pref enforce a PowerShell code signing block for this script.
        - Pref store script in a secure folder where the gmsa is the reader only
            with write to entragroupsync.log only.
#>
# #########################################################################
## Params
# Monitor groups which startwith
$StartsWith = 'Role -'
# Create Mode (AD / Both / None)
$CreateMode = 'AD'
# Update Mode (Add / Remove / Both)
$UpdateMode = 'Both'
# Delete Mode (AD / Both / None)
$DeleteMode = 'AD'
# Entra AppId 
$AppId = '864528a0-e44b-4d4e-85c8-3bcb03ebf03c'
# Entra TenantId
$TenantId = '6942ea75-0018-404e-a142-c2a7d1040d98'
# Entra App Thumbprint
$Thumbprint = '7F920BA3DFDE6D1F45E747A38D6EC181CFF2BB75'
# Email Address
$SendFromEmailAddress = 'pim@mcse.cloud'
# AD Group OU
$CreateADGroupsIn = 'OU=Role Groups,OU=Groups,OU=Custom,DC=ad,DC=mcse,DC=cloud'
# Loop Sleep Seconds
$SleepSeconds = 60
# Activation Email Template
$ActivationEmailTemplate = '.\emailtemplate_add.html'
# Removal Email Template
$RemovalEmailTemplate = '.\emailtemplate_remove.html'
# Log File
$LogFile = '.\EntraGroupSync.log'
# #########################################################################
## Functions
# Auth To Graph
function New-GraphAuth
{
    param([Parameter(Mandatory=$true)][string]$AppId,
          [Parameter(Mandatory=$true)][string]$TenantId,
          [Parameter(Mandatory=$true)][string]$Thumbprint)
    end
    {
        try {
            $Result = Connect-MgGraph -ClientId $AppId -TenantId $TenantId -CertificateThumbprint $Thumbprint
            if (!$Result) { throw }
            $Context = Get-MgContext
            Test-GraphPermissions -Scopes ($Context.Scopes -join ', ')
        } catch {
            Write-Log -EventType Error "Unable to authenticate to Graph ($($_)). Can not continue."
            Exit 1
        }
    }
}
# Check for Required Graph Permissions
function Test-GraphPermissions
{
    param([Parameter(Mandatory=$true)][string]$Scopes)
    end
    {
        Write-Log -EventType Verbose "Graph Scopes: $($Scopes)"

        $Missing = @('Group.Read.All','User.Read.All','GroupMember.Read.All','Mail.Send') |
                   Where-Object { $Scopes -notlike "*$_*" }

        if ($Missing) {
            Write-Log -EventType Error "Missing Graph API permissions: $($Missing -join ', '). Can not continue."
            Exit 1
        } else {
            Write-Log -EventType Verbose "Correct Scopes."
        }
    }
}
# Get Entra Groups
function Get-EntraGroups
{
    param([Parameter(Mandatory=$true)][string]$StartsWith)
    end
    {
        return Get-MgGroup -Filter "startsWith(displayName,'$($StartsWith)')" -All
    }
}
# Get AD Group
function Get-OnPremGroups
{
    param([Parameter(Mandatory=$true)][string]$StartsWith)
    end
    {
        return Get-ADGroup -Filter "Name -like '$($StartsWith)*'" -Properties adminDisplayName
    }
}
# New AD Group
function New-OnPremGroup
{
    param([Parameter(Mandatory=$true)][Microsoft.Graph.PowerShell.Models.MicrosoftGraphGroup]$EntraGroup,
          [Parameter(Mandatory=$true)][string]$CreateADGroupsIn)
    end
    {
        try {
            $OnPremGroup = Get-ADGroup -Filter "adminDisplayName -eq '$($EntraGroup.Id)'" -ErrorAction SilentlyContinue
            if ($null -eq $OnPremGroup) {     
                Write-Log -EventType Verbose "Provisioning AD Group ($($EntraGroup.DisplayName)) with ID ($($EntraGroup.Id)) in ($($CreateADGroupsIn))"   
                $Properties = @{
                    Name            = $EntraGroup.DisplayName.Substring(0, [Math]::Min(64, $EntraGroup.DisplayName.Length))
                    SamAccountName  = $EntraGroup.Id.Replace('-','').Substring(0, [Math]::Min(19, $EntraGroup.DisplayName.Length))
                    GroupCategory   = 'Security'
                    GroupScope      = 'Global'
                    DisplayName     = $EntraGroup.DisplayName
                    Path            = $CreateADGroupsIn
                    Description     = 'PIM Managed / Do Not Update Manually'  # $EntraGroup.Description
                    OtherAttributes = @{'adminDisplayName' = $EntraGroup.Id;}
                }
                $Properties.GetEnumerator() |% { Write-Log -EventType Verbose ("{0} = {1}" -f $_.Key, $_.Value) }
                New-ADGroup @Properties
            } else {
                Write-Log -EventType Verbose "AD Group ($($OnPremGroup.Name)) with ID ($($EntraGroup.Id)) in ($($CreateADGroupsIn)) already exists."
            }
        } catch {
            Write-Log -EventType Error $_
        }
    }
}
# Remove AD Group
function Remove-OnPremGroup
{
    param([Parameter(Mandatory=$true)][Microsoft.ActiveDirectory.Management.ADGroup]$OnPremGroup)
    end
    {
        Write-Log -EventType Verbose "Deleting AD Group ($($OnPremGroup.Name)) with DN ($($OnPremGroup.DistinguishedName))"

        try {
            Remove-ADGroup -Identity $OnPremGroup.DistinguishedName -Confirm:$false
        } catch {
            Write-Log -EventType Error $_
        }
    }
}
# Update AD Group
function Update-OnPremGroupMembership
{
    param([Parameter(Mandatory=$true)][Microsoft.Graph.PowerShell.Models.MicrosoftGraphGroup]$EntraGroup)
    end
    {
         $OnPremGroup = Get-ADGroup -Filter "adminDisplayName -eq '$($EntraGroup.Id)'" -ErrorAction SilentlyContinue
         if ($null -eq $OnPremGroup) {
            Write-Log -EventType Error "Unable to locate AD Group with adminDisplayname ($($EntraGroup.Id))"
         } else {
            Write-Log -EventType Verbose "Cloning Membership for Group ($($OnPremGroup.Name))"

            ## Store Entra Members
            <# 
                Unfortunately, you need to manually pull together the SIDs of the Entra Group members
                    and ensure that blank rows are removed (these would be non sync'd users).
            #>
            try {
                $EntraMembers = @()
                Get-MgGroupMember -GroupId $EntraGroup.Id |% {
                    $EntraMembers += (Get-MgUser -UserId $_.Id -Property 'onPremisesSecurityIdentifier').onPremisesSecurityIdentifier
                }
                $EntraMembers = @($EntraMembers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            } catch {
                Write-Log -EventType Error "Unable to store entra user SIDs ($($_)). Cannot continue."
                return
            }

            ## Store existing members to determine new entra memebrs.
            try {
                $ExistingMembers = Get-ADGroupMember -Identity $OnPremGroup -Recursive |
                                   Select -ExpandProperty SID |% { $_.Value }
                $ExistingMembers = @($ExistingMembers)
                $MembersToAdd    = $EntraMembers   | Where-Object { $_ -notin $ExistingMembers }
                $MembersToRemove = $ExistingMembers | Where-Object { $_ -notin $EntraMembers }
            } catch {
                Write-Log -EventType Error "Unable to store existing group members ($($_)). Cannot continue."
                return
            }

            ## Handle empty membership
            Write-Log -EventType Verbose "Entra Member Count ($($EntraMembers.Count))."
            Write-Log -EventType Verbose "AD Member Count ($($ExistingMembers.Count))."
            Write-Log -EventType Verbose "Members to be added (SIDs): $($MembersToAdd -join ', ')"
            Write-Log -EventType Verbose "Members to be removed (SIDs): $($MembersToRemove -join ', ')"

            ## Handle both groups are already empty
            if ($EntraMembers.Count -eq 0 -and $ExistingMembers.Count -eq 0) {
                Write-Log -EventType Verbose "Both groups are empty. Return."
                return
            } 

            ## Handle SID lists (Entra Sync'd Users and AD Users) are the same.
            if ($MembersToAdd.Count -eq 0 -and $MembersToRemove.Count -eq 0) {
                Write-Log -EventType Verbose "Both groups have same AD users. Return."
                return
            }

            ## Add new members
            if ($MembersToAdd.Count -gt 0) {
                try {
                    Write-Log -EventType Verbose "Updating membership (add)."
                    Add-ADGroupMember -Identity $OnPremGroup -Members $MembersToAdd
                } catch {
                    Write-Log -EventType Error "Unable to update AD group members ($($_)). Cannot continue."
                }

                ## Notify New Entra Members
                try {
                    $MembersToAdd |% {
                        New-AddCompleteEmail -SendFromEmailAddress $SendFromEmailAddress `
                                             -GroupName $OnPremGroup.Name `
                                             -SID $_ `
                                             -EmailTemplate $ActivationEmailTemplate
                    }
                } catch {
                    Write-Log -EventType Error "Unable to send notification emails ($($_)). Cannot continue."
                }
            }

            ## Remove old members
            if ($MembersToRemove.Count -gt 0) {
                try {
                    Write-Log -EventType Verbose "Updating membership (remove)."
                    Remove-ADGroupMember -Identity $OnPremGroup -Members $MembersToRemove -Confirm:$false
                } catch {
                    Write-Log -EventType Error "Unable to update AD group members ($($_)). Cannot continue."
                }

                ## Notify New Entra Members
                try {
                    $MembersToRemove |% {
                        New-RemoveCompleteEmail -SendFromEmailAddress $SendFromEmailAddress `
                                                -GroupName $OnPremGroup.Name `
                                                -SID $_ `
                                                -EmailTemplate $RemovalEmailTemplate
                    }
                } catch {
                    Write-Log -EventType Error "Unable to send notification emails ($($_)). Cannot continue."
                }
            }

         }
    }
}
# New Email notifying user activation complete 
function New-AddCompleteEmail
{
    param([Parameter(Mandatory=$true)][string]$SendFromEmailAddress,
          [Parameter(Mandatory=$true)][string]$EmailTemplate,
          [Parameter(Mandatory=$true)][string]$GroupName,
          [Parameter(Mandatory=$true)][string]$SID)
    end
    {
        try {
            $OnPremUser = Get-ADUser -Identity $SID -Properties mail
            if ($null -eq $OnPremUser) { throw }
            if ([string]::IsNullOrEmpty($OnPremUser.mail)) { throw }
        } catch {
            Write-Log -EventType Warning "Unable to get the email address for the added user ($($_)). Cannot continue."
            return
        }

        $BodyHtml = Get-Content $EmailTemplate -Raw
        $BodyHtml = $BodyHtml.Replace('{{GroupName}}', $GroupName).
                        Replace('{{Operation}}', 'Add')
        $Email = @{ 
            message = @{ 
                subject = "PIM: Your activation for $($GroupName) has been completed."     
                body = @{ 
                    contentType = "HTML"
                    content = $BodyHtml  
                } 
                toRecipients = @( 
                    @{ 
                        emailAddress = @{ 
                            address = $OnPremUser.mail.ToLower().Trim()                 
                        } 
                    } 
                ) 
            } 
            saveToSentItems = "false" 
        } 
        try {
            Send-MgUserMail -UserId $SendFromEmailAddress -BodyParameter $Email
        } catch {
             Write-Log -EventType Error "Sending activation email to ($($OnPremUser.mail.ToLower().Trim())) from ($($SendFromEmailAddress)) failed ($($_))."
            return
        }
        Write-Log -EventType Verbose "Sent activation email to ($($OnPremUser.mail.ToLower().Trim())) from ($($SendFromEmailAddress))."
    }
}
# New Email notifying user removal complete 
function New-RemoveCompleteEmail
{
    param([Parameter(Mandatory=$true)][string]$SendFromEmailAddress,
          [Parameter(Mandatory=$true)][string]$EmailTemplate,
          [Parameter(Mandatory=$true)][string]$GroupName,
          [Parameter(Mandatory=$true)][string]$SID)
    end
    {
        try {
            $OnPremUser = Get-ADUser -Identity $SID -Properties mail
            if ($null -eq $OnPremUser) { throw }
            if ([string]::IsNullOrEmpty($OnPremUser.mail)) { throw }
        } catch {
            Write-Log -EventType Warning "Unable to get the email address for the added user ($($_)). Cannot continue."
            return
        }

        $BodyHtml = Get-Content $EmailTemplate -Raw
        $BodyHtml = $BodyHtml.Replace('{{GroupName}}', $GroupName).
                        Replace('{{Operation}}', 'Remove')

        $Email = @{ 
            message = @{ 
                subject = "PIM: Your activation for $($GroupName) has ended."    
                body = @{ 
                    contentType = "HTML" 
                    content = $BodyHtml  
                } 
                toRecipients = @( 
                    @{ 
                        emailAddress = @{ 
                            address = $OnPremUser.mail.ToLower().Trim()                 
                        } 
                    } 
                ) 
            } 
            saveToSentItems = "false" 
        } 
        try {
            Send-MgUserMail -UserId $SendFromEmailAddress -BodyParameter $Email
        } catch {
             Write-Log -EventType Error "Sending removal email to ($($OnPremUser.mail.ToLower().Trim())) from ($($SendFromEmailAddress)) failed ($($_))."
            return
        }
        Write-Log -EventType Verbose "Sent removal email to ($($OnPremUser.mail.ToLower().Trim())) from ($($SendFromEmailAddress))."
    }
}
# Compare Lists
function Compare-Lists
{
    param([Parameter(Mandatory=$true)][string[]]$ListA,
          [Parameter(Mandatory=$true)][string[]]$ListB)
    end
    {
        Compare-Object -ReferenceObject $ListA -DifferenceObject $ListB
    }
}
# Create Action List
function New-ActionList
{
    param([Parameter(Mandatory=$true)][AllowEmptyCollection()][Microsoft.Graph.PowerShell.Models.MicrosoftGraphGroup[]]$EntraGroups,
          [Parameter(Mandatory=$true)][AllowEmptyCollection()][Microsoft.ActiveDirectory.Management.ADGroup[]]$OnPremGroups,
          [Parameter(Mandatory=$true)][ValidateSet('AD', 'Entra', 'Both', 'None')][string]$CreateMode,
          [Parameter(Mandatory=$true)][ValidateSet('Add', 'Remove', 'Both')][string]$UpdateMode,
          [Parameter(Mandatory=$true)][ValidateSet('AD', 'Entra', 'Both', 'None')][string]$DeleteMode)
    end
    {
        ## Verbose Stock Take
        Write-Log -EventType Verbose "($($EntraGroups.Count)) Entra groups to process."
        $EntraGroups |% { Write-Log -EventType Verbose $_.DisplayName }
        Write-Log -EventType Verbose "($($OnPremGroups.Count)) AD groups to process."
        $OnPremGroups |% { Write-Log -EventType Verbose $_.Name }

        ## Before anything are the group lists empty
        if ($EntraGroups.Count -eq 0 -and $OnPremGroups.Count -eq 0) {
            Write-Log -EventType Verbose "No groups to process."
            return;
        }
        #### AD Group Processing
        Write-Log -EventType Verbose "AD group processing."
        ### Group Provisioning and Deprovisioning
        Write-Log -EventType Verbose "AD group provisioning and deprovisioning."
        ## No AD Groups. Just mirror the Entra Groups
        if (($CreateMode -eq 'AD' -or $CreateMode -eq 'Both') -and ($EntraGroups.Count -gt 0 -and $OnPremGroups.Count -eq 0)) {
            Write-Log -EventType Verbose "No AD groups. Will create all Entra Groups."
            $EntraGroups |% { New-OnPremGroup -EntraGroup $_ -CreateADGroupsIn $CreateADGroupsIn }
        }
        ## No Entra Groups. Delete the AD Groups
        if (($DeleteMode -eq 'AD' -or $DeleteMode -eq 'Both') -and ($EntraGroups.Count -eq 0 -and $OnPremGroups.Count -gt 0)) {
            Write-Log -EventType Verbose "No Entra groups. Will remove all AD Groups."
            $OnPremGroups |% { Remove-OnPremGroup -OnPremGroup $_ }
        }
        ## Entra Groups and AD Groups. Determine Groups to be added.
        if (($CreateMode -eq 'AD' -or $CreateMode -eq 'Both') -and ($EntraGroups.Count -gt 0 -and $OnPremGroups.Count -gt 0)) {
            Write-Log -EventType Verbose "Looking for delta Entra groups to be created."
            $Delta = Compare-Object -ReferenceObject ($EntraGroups  | Select-Object -Expand DisplayName) `
                                    -DifferenceObject ($OnPremGroups  | Select-Object -Expand Name)
            <# 
                This is the inclusion operator. 
                We still check to see if the there is an Entra Group and an AD Group to improve processing efficiency.
                The less calls to Entra and Ad the better.
            #>                         
            $Delta |? {$_.SideIndicator -eq '<='} |% {
                $GroupName = $_.InputObject
                [Microsoft.Graph.PowerShell.Models.MicrosoftGraphGroup]$EntraGroup = $EntraGroups |? { $_.DisplayName -eq $GroupName } | Select -First 1
                if ($EntraGroup) {
                    [Microsoft.ActiveDirectory.Management.ADGroup]$OnPremGroup = $OnPremGroups |? { $_.adminDisplayName -eq $EntraGroup.Id } | Select -First 1
                    if ($null -eq $OnPremGroup) {
                        New-OnPremGroup -EntraGroup $EntraGroup -CreateADGroupsIn $CreateADGroupsIn
                    }
                }
            }
        }
        # Entra Groups and AD Groups. Determine Groups to be removed.
        if (($DeleteMode -eq 'AD' -or $DeleteMode -eq 'Both') -and ($EntraGroups.Count -gt 0 -and $OnPremGroups.Count -gt 0)) {
            Write-Log -EventType Verbose "Looking for delta AD groups to be removed."
            $Delta = Compare-Object -ReferenceObject ($EntraGroups  | Select-Object -Expand DisplayName) `
                                    -DifferenceObject ($OnPremGroups  | Select-Object -Expand Name)
            $Delta |? {$_.SideIndicator -eq '=>'} |% {
                $GroupName = $_.InputObject
                [Microsoft.ActiveDirectory.Management.ADGroup]$OnPremGroup = $OnPremGroups |? { $_.Name -eq $GroupName } | Select -First 1
                if ($OnPremGroup) {
                    Remove-OnPremGroup -OnPremGroup $OnPremGroup 
                }
            }
        }
        ## Group Membership cloning
        if (($UpdateMode -eq 'AD' -or $UpdateMode -eq 'Both') -and $EntraGroups.Count -gt 0) {
            Write-Log -EventType Verbose "Checking for updated membership."
            $EntraGroups |% {
                Update-OnPremGroupMembership -EntraGroup $_
            }
        }
    }
}
function Write-Log
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Information', 'Warning', 'Error', 'Verbose')]
        [string]$EventType,
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [bool]$WriteTextLog = $true,
        [Parameter(Mandatory=$false)]
        [bool]$WriteConsole = $true
    )
    end
    {
        if (Test-Path $LogFile -and (Get-Item $LogFile).Length -ge 5MB) { 
            Clear-Content $LogFile 
            "Log Rolled Over > 5MB" | Out-File $LogFile -Append
        }
        if ($WriteConsole) {
            switch ($EventType) {
                'Information' { Write-Host -ForegroundColor Cyan $Message }
                'Warning'     { Write-Warning  $Message }
                'Error'       { Write-Error    $Message }
                'Verbose'     { Write-Verbose  $Message }
            }
        }

        if ($WriteTextLog) {
           $Message | Out-File $LogFile -Append
        }
    }
}
# #########################################################################
## Main Loop
$CancellationToken = $false
do {
    try {
        # Start
        [datetime]$Start = [datetime]::Now
        Write-Log -EventType Information "$($Start) - Waking up / Running after ($($SleepSeconds)) seconds."
        # Authentication
        Write-Log -EventType Information "Authenticating."
        New-GraphAuth -AppId $AppId -TenantId $TenantId -Thumbprint $Thumbprint -Verbose
        # Store Groups
        Write-Log -EventType Information "Storing Groups."
        [Microsoft.Graph.PowerShell.Models.MicrosoftGraphGroup[]]$EntraGroups = @()
        [Microsoft.ActiveDirectory.Management.ADGroup[]]$OnPremGroups = @()
        $EntraGroups += Get-EntraGroups -StartsWith $StartsWith
        $OnPremGroups += Get-OnPremGroups -StartsWith $StartsWith
        # Process Groups
        Write-Log -EventType Information "Processing Actions."
        New-ActionList -EntraGroups $EntraGroups -OnPremGroups $OnPremGroups `
                    -CreateMode $CreateMode -UpdateMode $UpdateMode `
                    -DeleteMode $DeleteMode -Verbose
        # Complete
        $RunTime = New-TimeSpan -Start $Start -End ([datetime]::Now)
        Write-Log -EventType Information "Processing completed in ($($RunTime.Milliseconds) ms. | $($RunTime.Seconds) sec.)."
        # Sleep
        Start-Sleep -Seconds $SleepSeconds
    } catch {
         Write-Log -EventType Error "ERROR: $($_.Exception.Message)"
        Write-Log -EventType Error "STACK: $($_.Exception.StackTrace)"
        exit 1
    }

} until ($CancellationToken -eq $true)
