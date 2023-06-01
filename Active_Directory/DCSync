    DCSync is a technique for stealing the Active Directory password database by using the built-in Directory Replication Service Remote Protocol, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes.



    The crux of the attack is requesting a Domain Controller to replicate passwords via the DS-Replication-Get-Changes-All extended right. This is an extended access control right within AD, which allows for the replication of secret data.

    To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.

    \\Using Get-DomainUser to View adunn's Group Membership

    PS C:\htb> Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl

    PowerView can be used to confirm that this standard user does indeed have the necessary permissions assigned to their account. We first get the user's SID in the above command and then check all ACLs set on the domain object ("DC=inlanefreight,DC=local") using Get-ObjectAcl to get the ACLs associated with the object. Here we search specifically for replication rights and check if our user adunn (denoted in the below command as $sid) possesses these rights. The command confirms that the user does indeed have the rights.

    \\Using Get-ObjectAcl to Check adunn's Replication Rights

    PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
    PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl


    If we had certain rights over the user (such as WriteDacl), we could also add this privilege to a user under our control, execute the DCSync attack, and then remove the privileges to attempt to cover our tracks. DCSync replication can be performed using tools such as Mimikatz, Invoke-DCSync, and Impacket’s secretsdump.py. Let's see a few quick examples.


    Running the tool as below will write all hashes to files with the prefix inlanefreight_hashes. The -just-dc flag tells the tool to extract NTLM hashes and Kerberos keys from the NTDS file.

    
    \\Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py
    
    $ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 



    We can use the -just-dc-ntlm flag if we only want NTLM hashes or specify -just-dc-user <USERNAME> to only extract data for a specific user. Other useful options include -pwd-last-set to see when each account's password was last changed and -history if we want to dump password history, which may be helpful for offline password cracking or as supplemental data on domain password strength metrics for our client. The -user-status is another helpful flag to check and see if a user is disabled. 


    If we check the files created using the -just-dc flag, we will see that there are three: one containing the NTLM hashes, one containing Kerberos keys, and one that would contain cleartext passwords from the NTDS for any accounts set with reversible encryption enabled.

    While rare, we see accounts with these settings from time to time. It would typically be set to provide support for applications that use certain protocols that require a user's password to be used for authentication purposes.

    When this option is set on a user account, it does not mean that the passwords are stored in cleartext. Instead, they are stored using RC4 encryption. The trick here is that the key needed to decrypt them is stored in the registry (the Syskey) and can be extracted by a Domain Admin or equivalent. Tools such as secretsdump.py will decrypt any passwords stored using reversible encryption while dumping the NTDS file either as a Domain Admin or using an attack such as DCSync. If this setting is disabled on an account, a user will need to change their password for it to be stored using one-way encryption. Any passwords set on accounts with this setting enabled will be stored using reversible encryption until they are changed. We can enumerate this using the Get-ADUser cmdlet:

    PS C:\htb> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl


    \\\Checking for Reversible Encryption Option using Get-DomainUser (Powerview.ps1)

    PS C:\htb> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol


    \\\Performing the Attack with Mimikatz


    PS C:\htb> .\mimikatz.exe

    mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator

    