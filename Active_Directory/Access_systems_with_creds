 
 Typically, if we take over an account with local admin rights over a host, or set of hosts, we can perform a Pass-the-Hash attack to authenticate via the SMB protocol.

But what if we don't yet have local admin rights on any hosts in the domain?

There are several other ways we can move around a Windows domain:

    Remote Desktop Protocol (RDP) - is a remote access/management protocol that gives us GUI access to a target host

    PowerShell Remoting - also referred to as PSRemoting or Windows Remote Management (WinRM) access, is a remote access protocol that allows us to run commands or enter an interactive command-line session on a remote host using PowerShell

    MSSQL Server - an account with sysadmin privileges on an SQL Server instance can log into the instance remotely and execute queries against the database. This access can be used to run operating system commands in the context of the SQL Server service account through various methods


    We can enumerate this access in various ways. The easiest, once again, is via BloodHound, as the following edges exist to show us what types of remote access privileges a given user has:

    CanRDP
    CanPSRemote
    SQLAdmin

    We can also enumerate these privileges using tools such as PowerView and even built-in tools.



    \\\Remote Desktop


    Using PowerView, we could use the Get-NetLocalGroupMember function to begin enumerating members of the Remote Desktop Users group on a given host. Let's check out the Remote Desktop Users group on the MS01 host in our target domain


    \\Enumerating the Remote Desktop Users Group

    PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

    From the information above, we can see that all Domain Users (meaning all users in the domain) can RDP to this host. It is common to see this on Remote Desktop Services (RDS) hosts or hosts used as jump hosts. This type of server could be heavily used, and we could potentially find sensitive data (such as credentials) that could be used to further our access, or we may find a local privilege escalation vector that could lead to local admin access and credential theft/account takeover for a user with more privileges in the domain. Typically the first thing I check after importing BloodHound data is:

    Does the Domain Users group have local admin rights or execution rights (such as RDP or WinRM) over one or more hosts?


    \\Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound

    If we gain control over a user through an attack such as LLMNR/NBT-NS Response Spoofing or Kerberoasting, we can search for the username in BloodHound to check what type of remote access rights they have either directly or inherited via group membership under Execution Rights on the Node Info tab.


    \\Checking Remote Access Rights using BloodHound

    We could also check the Analysis tab and run the pre-built queries Find Workstations where Domain Users can RDP or Find Servers where Domain Users can RDP.



        \\\WinRM

    \\Enumerating the Remote Management Users Group


    PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"


    We can also utilize this custom Cypher query in BloodHound to hunt for users with this type of access. This can be done by pasting the query into the Raw Query box at the bottom of the screen and hitting enter.

    \\bloodhound for remote management users

    We can also utilize this custom Cypher query in BloodHound to hunt for users with this type of access. This can be done by pasting the query into the Raw Query box at the bottom of the screen and hitting enter.


    MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2


    \\\Establishing WinRM Session from Windows

    PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force

    PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)

    PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred


    \\From our Linux attack host, we can use the tool evil-winrm to connect.

    $ gem install evil-winrm

    $ evil-winrm -i 10.129.201.234 -u forend



    \\\SQL Server Admin


    BloodHound, once again, is a great bet for finding this type of access via the SQLAdmin edge. We can check for SQL Admin Rights in the Node Info tab for a given user or use this custom Cypher query to search:

    MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2

    We can use our ACL rights to authenticate with the wley user, change the password for the damundsen user and then authenticate with the target using a tool such as PowerUpSQL, which has a handy command cheat sheet. Let's assume we changed the account password to SQL1234! using our ACL rights. We can now authenticate and run operating system commands.


    \\\\Enumerating MSSQL Instances with PowerUpSQL

      https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet


    PS C:\htb> cd .\PowerUpSQL\
    PS C:\htb>  Import-Module .\PowerUpSQL.ps1
    PS C:\htb>  Get-SQLInstanceDomain


    We could then authenticate against the remote SQL server host and run custom queries or operating system commands. It is worth experimenting with this tool, but extensive enumeration and attack tactics against MSSQL are outside this module's scope.

    PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

    We can also authenticate from our Linux attack host using mssqlclient.py from the Impacket toolkit.

    We could then choose enable_xp_cmdshell to enable the xp_cmdshell stored procedure which allows for one to execute operating system commands via the database if the account in question has the proper access rights.


    Finally, we can run commands in the format xp_cmdshell <command>. Here we can enumerate the rights that our user has on the system and see that we have SeImpersonatePrivilege, which can be leveraged in combination with a tool such as JuicyPotato, PrintSpoofer, or RoguePotato to escalate to SYSTEM level privileges, depending on the target host, and use this access to continue toward our goal. These methods are covered in the SeImpersonate and SeAssignPrimaryToken of the Windows Privilege Escalation module. Try them out on this target if you would like to practice further!


    \\Enumerating our Rights on the System using xp_cmdshell

    xp_cmdshell whoami /priv


