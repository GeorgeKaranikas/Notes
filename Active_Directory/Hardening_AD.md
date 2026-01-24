# Pre-Windows 2000 Compatible Access Group

-  a built-in security principal (Organizational Unit) intended to maintain backward compatibility

- this group is pre-populated with the Authenticated Users group with any new deployment of Active Directory

- grants full read permissions on all users and groups in the domain

- So everyone who is able to take over a standard domain user account (or obtain NT AUTHORITY\SYSTEM rights over a domain-joined computer), they can proceed with detailed enumeration of the entire domain

- In older versions of AD , the **Everyone** group was also added to this OU, which also meant that the Anonymous-Identity (member of Everyone), was able to enumerate the domain.

# SMB Null Session

- can be used to retrieve data from AD, such as a listing of all users and the password policy

- Together, these can be used to mount a password spraying attack

```bash
$ netexec smb 192.168.195.138 --users 

$ netexec smb 192.168.195.138 --pass-pol
```

#### Remediation 

- Remove  **Everyone** from Pre-Windows 2000 Compatible Access Group
    - open ADSIEdit
    - Connect to **Action**
    - Go to  
- Disable `Network access: Let Everyone permissions apply to anonymous users` from `Default Domain Controllers Policy` in Group Policy
    - Open secpol.msc in Domain Controller

    - go to Computer Configuration --> Windows Settings --> Security Settings --> Local Policies --> Security Options

    - set "Network access: Let Everyone permissions apply to anonymous users" to disabled

    - execute `gpupdate /force`

# LDAP Anonymous Bind

- can be used to pull data such as a listing of users, groups, computers, and user account attributes

- This data can then be used to mount a password spraying attack or ASREPRoasting attack, similar to when an SMB null session

- Not a default on newer installations

[stig viewer](https://www.stigviewer.com/stigs/active_directory_forest/2025-05-15/finding/V-243503?utm_source=chatgpt.com)

```bash
$ ldapsearch -H ldap://192.168.195.147 -x -b "dc=wyrmwoodleg,dc=int" 
```

#### Remediation

- Open ADSI Edit (adsiedit.msc)

- right-click ADSI Edit --> Connect To -->, and choose Configuration as the Naming Contex

- browse to CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=yourdomain,DC=com, right-click on CN=Directory Service and select Properties

- in the Attribute Editor, find the [dsHeuristics](https://ad2049.com/kb/ds-heuristics) attribute and clear the value
    - This sets the [fLDAPBlockAnonOps](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5?utm_source=chatgpt.com) flag from 2 ( which translates to FALSE), to 0
    - So anonymous users are restricted to rootDSE LDAP Queries




# Anonymous RID Brute Forcing

- Anonymous users could query for AD User`s RelativeID (RID) in the domain controller

- If the forest configuration isn`t properly managed , this could lead to attackers gaining a list of AD Users

```bash
$ netexec smb {DC_ip} --rid-brute
```

#### Remediation

- In Group Policy Editor disable **Network access: Allow anonymous SID/name translation**

- Set **HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous** to 1 or 2



# LLMNR - NBT-NS 


|Abuse Case      |                         	Description  |                                                
|------------------|------------------------------------|
User mistyping                         |  	A user mistypes a UNC path or hostname, e.g., \\fileservr and DNS fails with LLMNR/NBT-NS broadcast enabled, rogue Responder server answers, and NTLMv2 hash is captured.
Windows Proxy Automatic Detection (WPAD) |	By default, Windows attempts to discover proxies using WPAD (i.e., wpad.wyrmwood.local). If no proxy host is defined in DNS (very common), the client will attempt the request for WPAD via LLMNR/NBT-NS. Responder answers, resulting in hash capture.
Chrome browser                           |	When a search term is typed into the Chrome search bar, the string will be treated as a search term and simultaneously checked for hostname resolution. Chrome also attempts to resolve randomized hostnames at startup, which will activate name resolution, often resulting in password hash capture.
Misconfigured applications/Services       |	Certain applications perform automatic network discovery or queries for resources (i.e., printers or file shares). If the proper DNS records do not exist, there will be a fallback to LLMNR/NBT-NS if enabled.
Unmanaged/legacy devices                 	|Unmanaged or legacy devices may trigger fallback name resolution mechanisms, exposing them to spoofed replies and subsequent credential leakage.
DNS server misconfiguration               |	If there is a DNS misconfiguration on either the client side or with the DNS server, there may be problems with name resolution, which could lead to successful poisoning attacks via these protocols.


#### Remediation LLMNR

- Create a new GPO

- Disable the multicast in **Computer Configuration → Administrative Templates → Network → DNS Client → turn off multicast name resolution**

- Link the Policy with the appropriate OUs.
    - Group Policy Manager → Right click the Unit → Create a GPO in this domain, and Link it here

- `gpupdate /force ` or wait 90 minutes to enforce the policy

#### Remediation NBT-NS

- Save a script in SYSVOL (\Domain\SYSVOL\Domain\scripts)

```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```

- Set a GPO for machines to execute the script

- Edit and go to **Computer Configuration > Policies > Windows Settings > Scripts (Startup/Shutdown) > Startup**

- Apply in OUs of interest

- Restart to enforce

- Double check with a script 

```powershell
PS C:\htb> Invoke-Command -ComputerName "MS01" -ScriptBlock {
 Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" |
 ForEach-Object {
 $netbios = Get-ItemProperty -Path $_.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue
 [PSCustomObject]@{
 Adapter = $_.PSChildName
 NetbiosOptions = $netbios.NetbiosOptions
 }
 }
}
```


# mDNS (multicast)

- In addition to LLMNR-NBTNS , mDNS is a network-local host discovery protocol common in smart devices and software like browsers, remote desktop etc.

- Fully disabling this protocol may cause trouble


- Disable inbound mDNS in Windows Defender Firewall for ALL profiles (Public, Private, Domain). This will prevent all inbound mDNS traffic but could cause issues for remote workers
- Disable mDNS just within the Domain profile, which will not affect remote workers but will block mDNS within the corporate network
- Disable mDNS in Windows Defender Firewall for outbound traffic. This is only necessary where high security is required, as blocking inbound mDNS traffic is typically sufficient


# DNS Spoofing over IPv6  

- Whenever a Windows computer is connected to the network, it broadcasts a DHCPv6 request asking for an IPv6 address

- an attacker can respond to these DHCPv6 queries via an attack called DHCPv6 spoofing

- The goal is to either capture NTLMv1/NTLMv2 password hashes or relay these authentication attempts to SMB, LDAP, etc.

#### Remediation

-  disable IPv6  by modifying : **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\\** and setting **DisabledComponents** to the value 0xFF 

- Bulk update via a GPO
    - Create a new GPO
    - browse to **Computer Configuration --> Preferences --> Windows Settings --> Registry**
    - right-click **New --> Registry Item**
        - Action: Update
        - Hive: HKEY_LOCAL_MACHINE
        - Key Path: SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters
        - Value Name: DisabledComponents
        - Value Type: REG_DWORD
        - Value Data: 255 (decimal) or 0xFF (hex)

# NTLM Relaying

- An attacker can coerce a user to authenticate to him and grab his credentials

- Then he can relay these credentials to various AD Services like SMB, LDAP etc. 

- This way he authenticates himself to AD, with another users rights and privileges, and perform various attacks.

#### Remediation

- Enforce SMB Signing
- Enforce LDAP Signing
- Enforce LDAP Channel Binding
- Disable support for NTLMv1
- Disable NTLM authentication wherever possible in favor of Kerberos
- Place privileged users in the Protected Users group
- Network segmentation


#### Remediation - MachineAccountQuota
- Set MachineAccountQuota to 0
    - This LDAP attribute controls the number of computer accounts that a user is permitted to create in an Active Directory
    - This allows an attacker to create a computer account that they control by specifying the username and password
    - this can be achieved using a response spoofing attack combined with an NTLM relay to the LDAP service
##### Check the value

```powershell
PS C:\>Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
```

##### Change the value

```powershell
PS C:\htb> Set-ADdomain -Identity wyrmwood.local -Replace @{"ms-DS-MachineAccountQuota"="0"} -Verbose
```

#### Remediation - SMB Signing

- You can check for smb signing with [Get-SmbClientConfiguration](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbclientconfiguration?view=windowsserver2025-ps)

```powershell
PS C:\> $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

Invoke-Command -ComputerName $computers -ScriptBlock {
 Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature
}
```
- You can also check for the 


```powershell
# SMB Server Registry settings
$serverKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$serverRequire = Get-ItemProperty -Path $serverKey -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
$serverEnable  = Get-ItemProperty -Path $serverKey -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue

# SMB Client Registry settings
$clientKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$clientRequire = Get-ItemProperty -Path $clientKey -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
$clientEnable  = Get-ItemProperty -Path $clientKey -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue

```

|Setting              |     	Value |	Meaning      |        
|------------------|---------- |---------- |         
RequireSecuritySignature 	|1    | 	Signing is required            
RequireSecuritySignature 	|0     	|Signing is not required        
EnableSecuritySignature  | 	1    | 	Signing is enabled (if needed)
EnableSecuritySignature   |	0     |	Signing is disabled   

##### Remediate via GPO

- In **Computer Configuration --> Windows Settings --> Security Settings --> Local Policies --> Security Options** set:
- **Microsoft network client: Digitally sign communications**, both  (always) and (if server agrees) to 1

- **Microsoft network server: Digitally sign communications** , both  (always) and (if server agrees) to 1


#### Remediation - LDAP Signing/LDAP Channel Binding

- LDAP Channel Binding applies to LDAP over SSL/TLS on port 636
- creates a unique fingerprint called a Channel Binding Token (CBT) to bind the TLS tunnel and LDAP application layer together

Feature   |                          	Purpose             |	Affected Protocol 	|Required to Stop LDAP Relays?|
|------|--------|-------------|-------------|
LDAP Signing            |           	Integrity check (mitigates tampering, some relays)  |         	LDAP (389)      |   	Yes        |                  
LDAP Channel Binding      |         	Ties TLS to authentication (mitigates MITM/relays over LDAPS) 	|LDAPS (636)  |     	Yes, if LDAPS is enabled      |

- Check for LDAP Signing

```powershell
PS C:\> Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity"
```

- 0 - Signing not required (vulnerable to LDAP relays)
- 1 - Signing supported but not required (still vulnerable to LDAP relays)
- 2 - Signing required (secured against LDAP relays)


- Change this with Set-ItemProperty and Invoke-Command Remotely on all servers.

- Or via a GPO
    -  In **the Default Domain Controller Policy**
    - Change **Computer Configuration --> Policies --> Windows Settings --> Security Settings --> Local Policies --> Domain controller: LDAP server signing requirements**

- Check for **LDAP Channel Binding**

- Supported by Server 2019 and forward, and not specified by default.

```powershell
PS C:\> Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding"
```

- 0 - Disabled (vulnerable to LDAPS relays)
- 1 - Compatibility mode (not fully secure)
- 2 - Channel Binding enforced (secured against LDAPS relays)

- Enable in **Default Domain Controller Policy**

- Under **Computer Configuration --> Policies --> Windows Settings --> Security Settings --> Local Policies --> Domain controller: LDAP server signing requirements**

- Set **Domain controller: LDAP server channel binding token requirements.** to always

# Remediating Open Shares

```powershell
$smbShares = Get-SmbShare
foreach ($share in $smbShares) {
    Write-Host "Share : $($share.Name)"
    $permissions = Get-SmbShareAccess -Name $share.Name
    foreach ($permission in $permissions) {
        Write-Host "  Account: $($permission.AccountName)"
        Write-Host "  Access: $($permission.AccessControlType)"
        Write-Host "  Rights: $($permission.AccessRight)"
         Revoke-SmbShareAccess -Name $share.Name -AccountName "Domain\UnauthorizedUser" -ErrorAction SilentlyContinue
    }
}
```

# Kerberos Pre-Authentication not required (ASREP Roasting)

#### Enum 

```powershell
Get-ADUSer -Filter { DoesNotRequirePreAuth -eq $true } 
```

#### Remediation

- Set the "Do not require Kerberos PreAuthentication" to false

```powershell
PS C:\>Get-ADUser -Identity svc-backup | Set-ADAccountControl -DoesNotRequirePreAuth $false -Verbose

PS C:\> Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } | Set-ADAccountControl -DoesNotRequirePreAuth $false -Verbose
```




