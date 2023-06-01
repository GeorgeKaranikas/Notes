
        \\\Exchange Related Group Membership


    A default installation of Microsoft Exchange within an AD environment (with no split-administration model) opens up many attack vectors, as Exchange is often granted considerable privileges within the domain (via users, groups, and ACLs). The group Exchange Windows Permissions is not listed as a protected group, but members are granted the ability to write a DACL to the domain object. This can be leveraged to give a user DCSync privileges. An attacker can add accounts to this group by leveraging a DACL misconfiguration (possible) or by leveraging a compromised account that is a member of the Account Operators group. It is common to find user accounts and even computers as members of this group. Power users and support staff in remote offices are often added to this group, allowing them to reset passwords. This GitHub repo (https://github.com/gdedrouas/Exchange-AD-Privesc) details a few techniques for leveraging Exchange for escalating privileges in an AD environment.


    The Exchange group Organization Management is another extremely powerful group (effectively the "Domain Admins" of Exchange) and can access the mailboxes of all domain users. It is not uncommon for sysadmins to be members of this group. This group also has full control of the OU called Microsoft Exchange Security Groups, which contains the group Exchange Windows Permissions.

    If we can compromise an Exchange server, this will often lead to Domain Admin privileges. Additionally, dumping credentials in memory from an Exchange server will produce 10s if not 100s of cleartext credentials or NTLM hashes. This is often due to users logging in to Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login.

            \\\PrivExchange

    The PrivExchange attack results from a flaw in the Exchange Server PushSubscription feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.

    The Exchange service runs as SYSTEM and is over-privileged by default (i.e., has WriteDacl privileges on the domain pre-2019 Cumulative Update). This flaw can be leveraged to relay to LDAP and dump the domain NTDS database. If we cannot relay to LDAP, this can be leveraged to relay and authenticate to other hosts within the domain. This attack will take you directly to Domain Admin with any authenticated domain user account.



        \\\Printer Bug

    The Printer Bug is a flaw in the MS-RPRN protocol (Print System Remote Protocol). This protocol defines the communication of print job processing and print system management between a client and a print server. To leverage this flaw, any domain user can connect to the spool's named pipe with the RpcOpenPrinter method and use the RpcRemoteFindFirstPrinterChangeNotificationEx method, and force the server to authenticate to any host provided by the client over SMB.

    The spooler service runs as SYSTEM and is installed by default in Windows servers running Desktop Experience. This attack can be leveraged to relay to LDAP and grant your attacker account DCSync privileges to retrieve all password hashes from AD.

    The attack can also be used to relay LDAP authentication and grant Resource-Based Constrained Delegation (RBCD) privileges for the victim to a computer account under our control, thus giving the attacker privileges to authenticate as any user on the victim's computer. This attack can be leveraged to compromise a Domain Controller in a partner domain/forest, provided you have administrative access to a Domain Controller in the first forest/domain already, and the trust allows TGT delegation, which is not by default anymore.

    The attack can also be used to relay LDAP authentication and grant Resource-Based Constrained Delegation (RBCD) privileges for the victim to a computer account under our control, thus giving the attacker privileges to authenticate as any user on the victim's computer. This attack can be leveraged to compromise a Domain Controller in a partner domain/forest, provided you have administrative access to a Domain Controller in the first forest/domain already, and the trust allows TGT delegation, which is not by default anymore.


    We can use tools such as the Get-SpoolStatus module from this (https://github.com/cube0x0/Security-Assessment) tool to check for machines vulnerable to the MS-PRN Printer Bug. This flaw can be used to compromise a host in another forest that has Unconstrained Delegation enabled, such as a domain controller. It can help us to attack across forest trusts once we have compromised one forest.


    \\\Enumerating for MS-PRN Printer Bug

    Import-Module .\SecurityAssessment.ps1

    PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

    
    
    
            \\\MS14-068

    This was a flaw in the Kerberos protocol, which could be leveraged along with standard domain user credentials to elevate privileges to Domain Admin. A Kerberos ticket contains information about a user, including the account name, ID, and group membership in the Privilege Attribute Certificate (PAC). The PAC is signed by the KDC using secret keys to validate that the PAC has not been tampered with after creation.

    The vulnerability allowed a forged PAC to be accepted by the KDC as legitimate. This can be leveraged to create a fake PAC, presenting a user as a member of the Domain Administrators or other privileged group. It can be exploited with tools such as the Python Kerberos Exploitation Kit (PyKEK) or the Impacket toolkit. The only defense against this attack is patching. The machine Mantis on the Hack The Box platform showcases this vulnerability.


            \\\Sniffing LDAP Credentials

    Many applications and printers store LDAP credentials in their web admin console to connect to the domain. These consoles are often left with weak or default passwords. Sometimes, these credentials can be viewed in cleartext. Other times, the application has a test connection function that we can use to gather credentials by changing the LDAP IP address to that of our attack host and setting up a netcat listener on LDAP port 389. When the device attempts to test the LDAP connection, it will send the credentials to our machine, often in cleartext. Accounts used for LDAP connections are often privileged, but if not, this could serve as an initial foothold in the domain. Other times, a full LDAP server is required to pull off this attack, as detailed in this post. 



            \\\\Enumerating DNS Records


    We can use a tool such as adidnsdump to enumerate all DNS records in a domain using a valid domain user account. This is especially helpful if the naming convention for hosts returned to us in our enumeration using tools such as BloodHound is similar to SRV01934.INLANEFREIGHT.LOCAL. If all servers and workstations have a non-descriptive name, it makes it difficult for us to know what exactly to attack. If we can access DNS entries in AD, we can potentially discover interesting DNS records that point to this same server, such as JENKINS.INLANEFREIGHT.LOCAL, which we can use to better plan out our attacks.

    The tool works because, by default, all users can list the child objects of a DNS zone in an AD environment. By default, querying DNS records using LDAP does not return all results. So by using the adidnsdump tool, we can resolve all records in the zone and potentially find something useful for our engagement. The background and more in-depth explanation of this tool and technique can be found in this post.

    On the first run of the tool, we can see that some records are blank, namely ?,LOGISTICS,?.

    \\Using adidnsdump

    $ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 

    $ head records.csv 

    If we run again with the -r flag the tool will attempt to resolve unknown records by performing an A query. Now we can see that an IP address of 172.16.5.240 showed up for LOGISTICS. While this is a small example, it is worth running this tool in larger environments. We may uncover "hidden" records that can lead to discovering interesting hosts.

    $ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r

    

    \\\\Finding Passwords in the Description Field using Get-Domain User


    PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

    \\\Checking for PASSWD_NOTREQD Setting using Get-DomainUser

    PS C:\htb> Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol




    
            \\\Group Policy Preferences (GPP) Passwords

    
    Group Policy Preferences (GPP) Passwords

    When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:

    Map drives (drives.xml)
    Create local users
    Create printer config files (printers.xml)
    Creating and updating services (services.xml)
    Creating scheduled tasks (scheduledtasks.xml)
    Changing local admin passwords.

    These files can contain an array of configuration data and defined passwords. The cpassword attribute value is AES-256 bit encrypted, but Microsoft published the AES private key on MSDN, which can be used to decrypt the password. Any domain user can read these files as they are stored on the SYSVOL share, and all authenticated users in a domain, by default, have read access to this domain controller share.

    \\Decrypting the Password with gpp-decrypt


    $ gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE


    \\Locating & Retrieving GPP Passwords with CrackMapExec

    $ crackmapexec smb -L | grep gpp


    It is also possible to find passwords in files such as Registry.xml when autologon is configured via Group Policy. This may be set up for any number of reasons for a machine to automatically log in at boot. If this is set via Group Policy and not locally on the host, then anyone on the domain can retrieve credentials stored in the Registry.xml file created for this purpose.

    \\Using CrackMapExec's gpp_autologin Module

    $ crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin


    A theme that we touch on throughout this module is password re-use. Poor password hygiene is common in many organizations, so whenever we obtain credentials, we should check to see if we can use them to access other hosts (as a domain or local user), leverage any rights such as interesting ACLs, access shares, or use the password in a password spraying attack to uncover password re-use and maybe an account that grants us further access towards our goal.





                \\\ASREPRoasting

    
    It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the Do not require Kerberos pre-authentication setting enabled. Many vendor installation guides specify that their service account be configured in this way. The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.

    With pre-authentication, a user enters their password, which encrypts a time stamp. The Domain Controller will decrypt this to validate that the correct password was used. If successful, a TGT will be issued to the user for further authentication requests in the domain. If an account has pre-authentication disabled, an attacker can request authentication data for the affected account and retrieve an encrypted TGT from the Domain Controller. This can be subjected to an offline password attack using a tool such as Hashcat or John the Ripper.

    ASREPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An SPN is not required. This setting can be enumerated with PowerView or built-in tools such as the PowerShell AD module.

    The attack itself can be performed with the Rubeus toolkit and other tools to obtain the ticket for the target account. If an attacker has GenericWrite or GenericAll permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again. Like Kerberoasting, the success of this attack depends on the account having a relatively weak password.


    Below is an example of the attack. PowerView can be used to enumerate users with their UAC value set to DONT_REQ_PREAUTH.

    \\\Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser

    PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl


    With this information in hand, the Rubeus tool can be leveraged to retrieve the AS-REP in the proper format for offline hash cracking. This attack does not require any domain user context and can be done by just knowing the SAM name for the user without Kerberos pre-auth. We will see an example of this using Kerbrute later in this section. Remember, add the /nowrap flag so the ticket is not column wrapped and is retrieved in a format that we can readily feed into Hashcat.

    PS C:\htb> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

    We can then crack the hash offline using Hashcat with mode 18200.

    \\\Cracking the Hash Offline with Hashcat

    $ hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 

    When performing user enumeration with Kerbrute, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.

    $ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 


    With a list of valid users, we can use Get-NPUsers.py from the Impacket toolkit to hunt for all users with Kerberoast pre-authentication not required. The tool will retrieve the AS-REP in Hashcat format for offline cracking for any found. We can also feed a wordlist such as jsmith.txt into the tool, it will throw errors for users that do not exist, but if it finds any valid ones without Kerberos pre-authentication, then it can be a nice way to obtain a foothold or further our access, depending on where we are in the course of our assessment. Even if we are unable to crack the AS-REP using Hashcat it is still good to report this as a finding to clients (just lower risk if we cannot crack the password) so they can assess whether or not the account requires this setting.


    \\Hunting for Users with Kerberoast Pre-auth Not Required

    $ GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 





                \\\\Group Policy Object (GPO) Abuse


    Group Policy provides administrators with many advanced settings that can be applied to both user and computer objects in an AD environment. Group Policy, when used right, is an excellent tool for hardening an AD environment by configuring user settings, operating systems, and applications. That being said, Group Policy can also be abused by attackers. If we can gain rights over a Group Policy Object via an ACL misconfiguration, we could leverage this for lateral movement, privilege escalation, and even domain compromise and as a persistence mechanism within the domain. Understanding how to enumerate and attack GPOs can give us a leg up and can sometimes be the ticket to achieving our goal in a rather locked-down environment.

    GPO misconfigurations can be abused to perform the following attacks:

        Adding additional rights to a user (such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege)
        
        Adding a local admin user to one or more hosts
        
        Creating an immediate scheduled task to perform any number of actions


    We can enumerate GPO information using many of the tools we've been using throughout this module such as PowerView and BloodHound. We can also use group3r, ADRecon, PingCastle, among others, to audit the security of GPOs in a domain.

    Using the Get-DomainGPO function from PowerView, we can get a listing of GPOs by name.

    \\Enumerating GPO Names with PowerView

    PS C:\htb> Get-DomainGPO |select displayname

    This can be helpful for us to begin to see what types of security measures are in place (such as denying cmd.exe access and a separate password policy for service accounts). We can see that autologon is in use which may mean there is a readable password in a GPO, and see that Active Directory Certificate Services (AD CS) is present in the domain. If Group Policy Management Tools are installed on the host we are working from, we can use various built-in GroupPolicy cmdlets such as Get-GPO to perform the same enumeration.

    \\Enumerating GPO Names with a Built-In Cmdlet

    PS C:\htb> Get-GPO -All | Select DisplayName

    Next, we can check if a user we can control has any rights over a GPO. Specific users or groups may be granted rights to administer one or more GPOs. A good first check is to see if the entire Domain Users group has any rights over one or more GPOs.

    \\Enumerating Domain User GPO Rights

    PS C:\htb> $sid=Convert-NameToSid "Domain Users"

    PS C:\htb> Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

    Here we can see that the Domain Users group has various permissions over a GPO, such as WriteProperty and WriteDacl, which we could leverage to give ourselves full control over the GPO and pull off any number of attacks that would be pushed down to any users and computers in OUs that the GPO is applied to. We can use the GPO GUID combined with Get-GPO to see the display name of the GPO.

    \\Converting GPO GUID to Name

    PS C:\htb Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532

    If we select the GPO in BloodHound and scroll down to Affected Objects on the Node Info tab, we can see that this GPO is applied to one OU, which contains four computer objects.

    