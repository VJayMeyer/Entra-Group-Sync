<# 
    Entra Group Sync – Deployment Script

    ROLES / PERMISSIONS:
      - Local Administrator on the server where Entra Group Sync will run
      - Domain Admin (KDS root key, gMSA, OU, AD perms)
      - Entra Global Admin (PIM groups, App Registration, consent)
      - Exchange Org Admin (shared mailbox, mail-enabled group, App Access Policy)
      - There are some manual tasks which are yet to be rolled into this installer:
          1. You need to update the Entr App Secret with the provisioned cert public cert.
          2. You need to make sure the gMSA has run as a batch job on the server where the
              task will run.

    NOTE:
      - Install PowerShell 7 manually first if needed:
        https://learn.microsoft.com/powershell/scripting/install/install-powershell-on-windows
#>

#=============================
# CONFIG – EDIT TO SUIT
#=============================

$DomainNetBios        = 'MCSE'
$GmsaName             = 'EntraGroupSync'
$GmsaSamAccount       = "$DomainNetBios\$GmsaName$"
$AppDisplayName       = 'Entra Group Sync'
$InstallPath          = 'C:\Program Files\Entra Group Sync'
$LogFilePath          = Join-Path $InstallPath 'EntraGroupSync.log'

# AD OU where role groups live
$OuParentDn           = 'OU=Groups,OU=Custom,DC=ad,DC=mcse,DC=cloud'
$RoleGroupsOuDn       = "OU=Role Groups,$OuParentDn"

# Git repo
$RepoUrl              = 'https://github.com/VJayMeyer/Entra-Group-Sync.git'

# Mail identities
$SharedMailboxSmtp    = 'pim@mcse.cloud'
$ScopeGroupSmtp       = 'pim-scope@mcse.cloud'

#=============================
# STEP 1 – Install modules / tools
#=============================

Write-Host 'STEP 1: Installing required modules and RSAT (if missing)...' -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope AllUsers -Force
}

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Scope AllUsers -Force
}

# RSAT-ADDS (on a server)
if (-not (Get-WindowsFeature RSAT-ADDS).Installed) {
    Install-WindowsFeature RSAT-ADDS -IncludeAllSubFeature | Out-Null
}

Write-Host 'STEP 1 complete.' -ForegroundColor Green

#=============================
# STEP 2 – KDS root key & gMSA
#=============================

Write-Host 'STEP 2: Creating / validating KDS root key and gMSA...' -ForegroundColor Cyan

# KDS root key (only once per forest – safe if it already exists)
if (-not (Get-KdsRootKey -ErrorAction SilentlyContinue)) {
    Add-KdsRootKey -EffectiveImmediately | Out-Null
    Write-Host 'KDS root key created.' -ForegroundColor Yellow
}

# Create gMSA if needed
if (-not (Get-ADServiceAccount -Identity $GmsaName -ErrorAction SilentlyContinue)) {
    $Domain = Get-ADDomain
    New-ADServiceAccount -Name $GmsaName `
        -DNSHostName "$GmsaName.$($Domain.DNSRoot)" `
        -PrincipalsAllowedToRetrieveManagedPassword 'Domain Controllers' `
        | Out-Null
    Write-Host "gMSA $GmsaName created." -ForegroundColor Yellow
}

# Install gMSA on this server
Install-ADServiceAccount $GmsaName -ErrorAction Stop
if (Test-ADServiceAccount $GmsaName) {
    Write-Host "gMSA $GmsaName is usable on this server." -ForegroundColor Green
} else {
    Write-Warning "gMSA $GmsaName failed Test-ADServiceAccount – fix this before continuing."
}

#=============================
# STEP 3 – Create OU & delegate group management
#=============================

Write-Host 'STEP 3: Creating Role Groups OU and delegating permissions...' -ForegroundColor Cyan

# Ensure parent OU exists (you may already have this)
try {
    $ParentOu = Get-ADOrganizationalUnit -Identity $OuParentDn -ErrorAction Stop
} catch {
    Write-Warning "Parent OU $OuParentDn does not exist. Create it first or adjust the script."
    $ParentOu = $null
}

if ($ParentOu) {
    # Create Role Groups OU if missing
    try {
        $RoleOu = Get-ADOrganizationalUnit -Identity $RoleGroupsOuDn -ErrorAction Stop
        Write-Host "OU already exists: $RoleGroupsOuDn" -ForegroundColor Yellow
    } catch {
        New-ADOrganizationalUnit -Name 'Role Groups' -Path $OuParentDn -ProtectedFromAccidentalDeletion $true | Out-Null
        Write-Host "Created OU: $RoleGroupsOuDn" -ForegroundColor Yellow
    }

    # Delegate group management to gMSA (GenericAll on group objects in that OU)
    dsacls $RoleGroupsOuDn /G "$GmsaSamAccount:GA;group" /I:S | Out-Null
    Write-Host "Delegated group management in $RoleGroupsOuDn to $GmsaSamAccount." -ForegroundColor Green
}

#=============================
# STEP 4 – Clone repo & set file permissions
#=============================

Write-Host 'STEP 4: Cloning Entra Group Sync repo and setting file permissions...' -ForegroundColor Cyan

if (-not (Test-Path $InstallPath)) {
    git clone $RepoUrl $InstallPath
} else {
    Write-Host "Install path $InstallPath already exists – skipping git clone." -ForegroundColor Yellow
}

# Folder read for gMSA
icacls $InstallPath /grant "$GmsaSamAccount:(R)" | Out-Null

# Ensure log file exists and give Full to gMSA
if (-not (Test-Path $LogFilePath)) {
    New-Item -ItemType File -Path $LogFilePath -Force | Out-Null
}
icacls $LogFilePath /grant "$GmsaSamAccount:(F)" | Out-Null

Write-Host 'STEP 4 complete.' -ForegroundColor Green

#=============================
# STEP 5 – Self-signed cert & private-key ACL
#=============================

Write-Host 'STEP 5: Creating self-signed certificate and granting gMSA key access...' -ForegroundColor Cyan

$Cert = New-SelfSignedCertificate `
    -Subject "CN=Entra Group Sync" `
    -DnsName "EntraGroupSync" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -KeyExportPolicy None `
    -KeyUsage DigitalSignature `
    -KeySpec Signature `
    -NotAfter ([datetime]::Now.AddYears(10))

Write-Host "Created certificate with Thumbprint: $($Cert.Thumbprint)" -ForegroundColor Yellow

# Grant gMSA read on private key
$KeyName = $Cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$KeyPath = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$KeyName"
icacls $KeyPath /grant "$GmsaSamAccount:(R)" | Out-Null

Write-Host "Granted $GmsaSamAccount read access to certificate private key." -ForegroundColor Green

#=============================
# STEP 6 – Entra App + Graph permissions
#=============================

Write-Host 'STEP 6: Creating Entra application and assigning Graph app permissions...' -ForegroundColor Cyan

Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.ReadWrite.All'

# Create or reuse application
$App = Get-MgApplication -Filter "displayName eq '$AppDisplayName'" | Select-Object -First 1
if (-not $App) {
    $App = New-MgApplication -DisplayName $AppDisplayName
    Write-Host "Created Entra app: $($App.DisplayName) ($($App.AppId))" -ForegroundColor Yellow
} else {
    Write-Host "Using existing Entra app: $($App.DisplayName) ($($App.AppId))" -ForegroundColor Yellow
}

# Service principal for this app
$AppServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$($App.AppId)'" | Select-Object -First 1
if (-not $AppServicePrincipal) {
    $AppServicePrincipal = New-MgServicePrincipal -AppId $App.AppId
}

# Microsoft Graph SP
$GraphServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" | Select-Object -First 1

# Graph app roles we want
$GraphAppRoles = @(
    '5b567255-7703-4780-807c-7be8301ae99b', # Group.Read.All
    '98830695-27a2-44f7-8c18-0c3ebc9698f6', # GroupMember.Read.All
    'df021288-bdef-4463-88db-98f22de89214', # User.Read.All
    'e383f46e-2787-4529-855e-0e479a3ffac0'  # Mail.Send
) | ForEach-Object {
    @{
        id   = [guid]$_
        type = 'Role'
    }
}

$RequiredResourceAccess = @(
    @{
        resourceAppId  = $GraphServicePrincipal.AppId
        resourceAccess = $GraphAppRoles
    }
)

Update-MgApplication -ApplicationId $App.Id -RequiredResourceAccess $RequiredResourceAccess

# Grant admin consent by creating app role assignments
foreach ($Role in $GraphAppRoles) {
    $Existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AppServicePrincipal.Id `
        | Where-Object AppRoleId -eq $Role.id

    if (-not $Existing) {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $AppServicePrincipal.Id `
            -PrincipalId        $AppServicePrincipal.Id `
            -ResourceId         $GraphServicePrincipal.Id `
            -AppRoleId          $Role.id `
            | Out-Null
    }
}

$TenantId = (Get-MgContext).TenantId

Write-Host "Entra app configured. AppId: $($App.AppId)  TenantId: $TenantId" -ForegroundColor Green
Write-Host "Update your EntraGroupSync.ps1 with AppId, TenantId and certificate Thumbprint as required." -ForegroundColor Yellow

#=============================
# STEP 7 – Shared mailbox, scope group, App Access Policy
#=============================

Write-Host 'STEP 7: Creating shared mailbox, scope group and application access policy...' -ForegroundColor Cyan

Connect-ExchangeOnline

# Shared mailbox
$Mailbox = Get-Mailbox -Identity $SharedMailboxSmtp -ErrorAction SilentlyContinue
if (-not $Mailbox) {
    $Mailbox = New-Mailbox -Shared -Name 'Entra Group Sync' -PrimarySmtpAddress $SharedMailboxSmtp
    Write-Host "Created shared mailbox $SharedMailboxSmtp" -ForegroundColor Yellow
}

# Mail-enabled security group
$PolicyGroup = Get-DistributionGroup -Identity $ScopeGroupSmtp -ErrorAction SilentlyContinue
if (-not $PolicyGroup) {
    $PolicyGroup = New-DistributionGroup -Name 'Entra Group Sync Scope' -Type Security -PrimarySmtpAddress $ScopeGroupSmtp
    Write-Host "Created mail-enabled security group $ScopeGroupSmtp" -ForegroundColor Yellow
}

# Ensure mailbox is in the scope group
$PolicyGroupMembers = Get-DistributionGroupMember -Identity $PolicyGroup.Identity -ResultSize Unlimited
if (-not ($PolicyGroupMembers | Where-Object PrimarySmtpAddress -eq $SharedMailboxSmtp)) {
    Add-DistributionGroupMember -Identity $PolicyGroup.Identity -Member $SharedMailboxSmtp
    Write-Host "Added $SharedMailboxSmtp to $ScopeGroupSmtp." -ForegroundColor Green
}

# Application access policy (restrict Mail.Send)
$ExistingPolicy = Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue | Where-Object AppId -eq $App.AppId
if (-not $ExistingPolicy) {
    New-ApplicationAccessPolicy `
        -AccessRight RestrictAccess `
        -AppId $App.AppId `
        -PolicyScopeGroupId $PolicyGroup.Identity `
        -Description "Allow Entra Group Sync app to send mail only as scoped addresses." | Out-Null
    Write-Host "Created Application Access Policy for AppId $($App.AppId)." -ForegroundColor Green
} else {
    Write-Host "Application Access Policy for AppId $($App.AppId) already exists." -ForegroundColor Yellow
}

#=============================
# STEP 8 – Scheduled Task
#=============================

Write-Host 'STEP 8: Creating scheduled task for Entra Group Sync...' -ForegroundColor Cyan

$ScriptArgs = '-ExecutionPolicy Bypass -NoProfile -File "C:\Program Files\Entra Group Sync\EntraGroupSync.ps1"'

$Action = New-ScheduledTaskAction `
    -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' `
    -Argument $ScriptArgs `
    -WorkingDirectory $InstallPath

$Trigger = @(
    New-ScheduledTaskTrigger -AtStartup
    New-ScheduledTaskTrigger -Once -At (Get-Date).Date `
        -RepetitionInterval (New-TimeSpan -Minutes 5) `
        -RepetitionDuration (New-TimeSpan -Days 30)
)

# gMSA uses LogonType ServiceAccount so it runs whether user is logged on or not
$Principal = New-ScheduledTaskPrincipal `
    -UserId    $GmsaSamAccount `
    -LogonType ServiceAccount `
    -RunLevel  Highest

$Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName 'Entra Group Sync' `
    -Action   $Action `
    -Trigger  $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Force | Out-Null

Write-Host 'Scheduled task "Entra Group Sync" created.' -ForegroundColor Green

Write-Host 'Deployment complete. Check the log file and Task Scheduler history for the first run.' -ForegroundColor Cyan
