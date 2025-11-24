# Entra Group Sync

Entra Group Sync keeps selected Entra ID PIM groups in sync with on-prem AD groups and sends users email when they’re added or removed from role groups.

---

## 1. Prerequisites

You’ll need:

- **Local Administrator** on the Entra Group Sync server  
- **Domain Admin** in AD (for KDS root key, gMSA, OU, ACLs)  
- **Entra ID Global Administrator** (for the App Registration and consent)  
- **Exchange Online admin rights** (for the shared mailbox / mail-enabled security group)

Also install:

- PowerShell 7 (x64) – from Microsoft  
- Git (any recent version)

---

## 2. Clone the repo

On the server that will run Entra Group Sync:

```powershell
git clone https://github.com/VJayMeyer/Entra-Group-Sync.git "C:\Program Files\Entra Group Sync"
cd "C:\Program Files\Entra Group Sync"
```

---

## 3. Configure `Deployment.ps1`

Open `Deployment.ps1` in your editor and update the **config section at the top**:

```powershell
$DomainNetBios        = 'MCSE'                          # Your NetBIOS domain name
$GmsaName             = 'EntraGroupSync'                # Name of the gMSA to create/use
$AppDisplayName       = 'Entra Group Sync'              # Entra App Registration display name
$InstallPath          = 'C:\Program Files\Entra Group Sync'

$OuParentDn           = 'OU=Groups,OU=Custom,DC=ad,DC=mcse,DC=cloud'
$RoleGroupsOuDn       = "OU=Role Groups,$OuParentDn"

$SharedMailboxSmtp    = 'pim@mcse.cloud'                # Shared mailbox used to send notifications
$ScopeGroupSmtp       = 'pim-scope@mcse.cloud'          # Mail-enabled security group for Graph Mail.Send scope
```

Adjust these to match **your** AD structure and email addresses.

---

## 4. Run the deployment script

From an elevated PowerShell window **on the Entra Group Sync server**:

```powershell
cd "C:\Program Files\Entra Group Sync"
Set-ExecutionPolicy RemoteSigned -Scope Process -Force

.\Deployment.ps1
```

What `Deployment.ps1` does for you:

1. Installs required modules and RSAT (Graph, ExchangeOnline, ADDS).
2. Creates / validates:
   - KDS root key (if not present)
   - gMSA (`$GmsaName`) and installs it on the server
3. Creates the **Role Groups OU** and delegates group management to the gMSA.
4. Ensures repo + log path and ACLs for the gMSA.
5. Creates a **self-signed certificate** and grants the gMSA access to the private key.
6. Creates / configures the **Entra App Registration** with required Graph app permissions.
7. Creates the **shared mailbox**, **mail-enabled scope group**, and **Application Access Policy** for Mail.Send.
8. Creates the **Scheduled Task** that runs `EntraGroupSync.ps1` as the gMSA every 5 minutes and at startup.

When the script finishes, you should see:

- AppId and TenantId values in the output
- A scheduled task called **“Entra Group Sync”**
- A log file at `C:\Program Files\Entra Group Sync\EntraGroupSync.log`

---

## 5. Configure `EntraGroupSync.ps1`

Next, edit the **configuration block** at the top of `EntraGroupSync.ps1`. At minimum:

```powershell
# Monitor groups which start with this string
$StartsWith = 'PIM - Active Directory -'

# Create / Update / Delete modes
$CreateMode  = 'AD'    # AD / Both / None
$UpdateMode  = 'Both'  # Add / Remove / Both
$DeleteMode  = 'AD'    # AD / Both / None

# Entra AppId and TenantId (from Deployment.ps1 output / Entra portal)
$AppId    = '<your-app-id-here>'
$TenantId = '<your-tenant-id-here>'

# Certificate thumbprint (from Deployment.ps1 output)
$Thumbprint = '<your-cert-thumbprint-here>'

# Notification email settings
$SendFromEmailAddress    = 'pim@yourdomain.com'
$ActivationEmailTemplate = '.\emailtemplate_add.html'
$RemovalEmailTemplate    = '.\emailtemplate_remove.html'

# AD OU where role groups are created
$CreateAdGroupsIn = 'OU=Role Groups,OU=Groups,OU=Custom,DC=ad,DC=your,DC=domain'
```

Adjust:

- `$StartsWith` to match the **PIM / role group naming pattern** you want to sync.
- `$CreateAdGroupsIn` to match the OU you just delegated.
- `$SendFromEmailAddress` to the shared mailbox you configured.

---

## 6. Test the sync

1. From the server, run the script **once** manually in PowerShell 7:

   ```powershell
   pwsh
   cd "C:\Program Files\Entra Group Sync"
   .\EntraGroupSync.ps1
   ```

   Check for obvious errors (Graph auth, AD, email).

2. Start the scheduled task:

   - Open **Task Scheduler**
   - Run **“Entra Group Sync”**
   - Confirm status and last run result

3. Watch the log file:

   ```powershell
   Get-Content "C:\Program Files\Entra Group Sync\EntraGroupSync.log" -Tail 50 -Wait
   ```

You should see:

- Successful Graph authentication  
- Detection / creation of AD role groups under your target OU  
- Membership adds/removes as users are added/removed from PIM-managed Entra groups  
- Notification emails being sent from the shared mailbox

---

## 7. Ongoing operations

- **Add new PIM groups** following your `$StartsWith` pattern: they’ll be picked up automatically.
- Make sure that **the activation notifcations are disabled** as the email will come from Entra Group Sync.

<img width="606" height="306" alt="image" src="https://github.com/user-attachments/assets/af441b5e-2811-48e4-9bd3-94fffae65988" />

