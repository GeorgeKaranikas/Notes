


# 4672 : Special Privilege`s Logon (Special privileges assigned to new logon)


- Subject:

    - Security ID [Type = SID]: SID of account
    - Account Name [Type = UnicodeString]: the name of the account 
    - Logon ID [Type = HexInt64]: hexadecimal value that can help you correlate this event with recent events that might contain the same Logon ID
    - Privileges [Type = UnicodeString]: the list of sensitive privileges

- Notes : If Security ID is different from SYSTEM, NETWORK SERVICE,LOCAL SERVICE, the logon is suspicious and needs to be investigated
- Some Privileges should never be assigned to anyone on the system in some cases.

### ATTACK MITRE Technique 

Access Token Manipulation - ID: T1134

# 4673: A privileged service was called

This event generates when an attempt was made to perform privileged system service operations.

- Subject:

    - Security ID [Type = SID]: SID of account that requested privileged operation
    - Account Name [Type = UnicodeString]: the name of the account that requested privileged operation.
    - Logon ID [Type = HexInt64]
- Service:
    - Service Name [Type = UnicodeString] [Optional]: supplies a name of the privileged subsystem service or function.
- Process :
    - Process ID [Type = Pointer]: hexadecimal Process ID of the process that attempted to call the privileged service
    - Process Name [Type = UnicodeString]
- Service Request Information:

    - Privileges [Type = UnicodeString]: the list of user privileges which were requested.


### Notes 
- If Subject\Security ID is not one of these well-known security principals: LOCAL SYSTEM, NETWORK SERVICE, LOCAL SERVICE ,the call is suspicious and needs investigation
- Exclude Processes well known for generating a lot of these events if needed
- If you have a pre-defined list of restricted substrings or words in process names (for example, “mimikatz” or “cain.exe”), check for these substrings in “Process Name.”


### ATTACK MITRE Technique 

Access Token Manipulation - ID: T1134




# 4674 : An operation was attempted on a privileged object

This event generates when an attempt is made to perform privileged operations on a protected subsystem object after the object is already opened.

- Subject:

    - Security ID [Type = SID]: SID of account that requested privileged operation
    - Account Name [Type = UnicodeString]: the name of the account that requested privileged operation.
    - Logon ID [Type = HexInt64]

- Object:
    - Object Name [Type = UnicodeString] [Optional]: the name of the object that was accessed during the operation.
- Process :
    - Process ID [Type = Pointer]: hexadecimal Process ID of the process that attempted to call the privileged service
    - Process Name [Type = UnicodeString]
- Requested Operation:

    - Desired Access [Type = UnicodeString]: The desired access mask. This mask depends on Object Server and Object Type parameters values.
    - Privileges [Type = UnicodeString]

### Notes 
- If Subject\Security ID is not one of these well-known security principals: LOCAL SYSTEM, NETWORK SERVICE, LOCAL SERVICE ,the call is suspicious and needs investigation


# 4703 : A user right was adjusted 

This event generates when token privileges were enabled or disabled for a specific accounts token


- Subject:

    - Security ID [Type = SID]: SID of account that requested the “enable” or “disable” operation for Target Account privileges
    - Account Name [Type = UnicodeString]: the name of the account that requested the “enable” or “disable” operation for Target Account privileges.
    - Logon ID [Type = HexInt64]: hexadecimal value that can help you correlate this event with recent events that might contain the same Logon ID
- Target Account:

    - Security ID [Type = SID]: SID of account for which privileges were enabled or disabled
    - Account Name [Type = UnicodeString]: the name of the account for which privileges were enabled or disabled.

- Process Information:

    - Process ID [Type = Pointer]
    - Process Name [Type = UnicodeString]: full path and the name of the executable for the process.
    - Enabled Privileges [Type = UnicodeString]

### Notes

- Microsoft Configuration Manager makes a lot 4703 events

### ATTACK MITRE Technique 

Access Token Manipulation - ID: T1134


# 4768 : A Kerberos authentication ticket (TGT) was requested

[msdn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)

This event generates **in Domain Controller** every time Key Distribution Center issues a Kerberos Ticket Granting Ticket (TGT).

- Account Information:

    - User account
    - Computer account

# 4769 : A Kerberos service ticket(TGS) was requested

[msdn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)

Generates on Domain controllers

If TGS issue fails then you'll see Failure event with Failure Code field not equal to “0x0”.

Events with Failure Code “0x20” means that a TGS ticket has expired.



# 4886 : Certificate Services received a certificate request 

When the Certification Authority receives a certificate reqeuest it logs this event. 

! This event event is only logged if "Issue and manage certificate requests" is enabled on the Audit tab of the CA's properties in Certificate Services MMC snap-in .which is desabled by default.

### Description fields

Request ID
Requester
Attributes
Subject from CSR
SAN from CSR
Requested Template
RequestOSVersion
RequestCSPProvider
RequestClientInfo
Authentication Service
Authentication Level
DCOMorRPC
