The environment consists of the following machines and their corresponding IP addresses:

    DC1: 172.16.18.3
    DC2: 172.16.18.4
    Server01: 172.16.18.10
    PKI: 172.16.18.15
    WS001: DHCP or 172.16.18.25 (depending on the section)
    Kali Linux: DHCP or 172.16.18.20 (depending on the section)



# Kerberoasting

### Description

In Active Directory, a Service Principal Name (SPN) is a unique service instance identifier. Kerberos uses SPNs for authentication to associate a service instance with a service logon account, which allows a client application to request that the service authenticate an account even if the client does not have the account name. When a Kerberos TGS service ticket is asked for, it gets encrypted with the service account's NTLM password hash.

Kerberoasting is a post-exploitation attack that attempts to exploit this behavior by obtaining a ticket and performing offline password cracking to open the ticket. If the ticket opens, then the candidate password that opened the ticket is the service account's password. The success of this attack depends on the strength of the service account's password. Another factor that has some impact is the encryption algorithm used when the ticket is created, with the likely options being:

-    AES
-    RC4
-    DES 

### Attack path

To obtain crackable tickets, we can use Rubeus. When we run the tool with the kerberoast action without specifying a user, it will extract tickets for every user that has an SPN registered (this can easily be in the hundreds in large environments):

```
PS C:\> .\Rubeus.exe kerberoast /outfile:spn.txt
```

We can use hashcat with the hash-mode (option -m) 13100 for a Kerberoastable TGS.
```
$ hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"
```

(If hashcat gives an error, we may need to pass --force as an argument at the end of the command.)

Alternatively, the captured TGS hashes can be cracked with John The Ripper:

```
$ sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot
```

### Prevention

The success of this attack depends on the strength of the service account's password. While we should limit the number of accounts with SPNs and disable those no longer used/needed, we must ensure they have strong passwords. For any service that supports it, the password should be 100+ random characters (127 being the maximum allowed in AD), which ensures that cracking the password is practically impossible.

There is also what is known as Group Managed Service Accounts (GMSA), which is a particular type of a service account that Active Directory automatically manages; this is a perfect solution because these accounts are bound to a specific server, and no user can use them anywhere else. Additionally, Active Directory automatically rotates the password of these accounts to a random 127 characters value. There is a caveat: not all applications support these accounts, as they work mainly with Microsoft services (such as IIS and SQL) and a few other apps that have made integration possible.When in doubt, do not assign SPNs to accounts that do not need them. Ensure regular clean-up of SPNs set to no longer valid services/servers.


### Detection

When a TGS is requested, an event log with ID 4769 is generated. However, AD also generates the same event ID whenever a user attempts to connect to a service, which means that the volume of this event is gigantic, and relying on it alone is virtually impossible to use as a detection method If we happen to be in an environment where all applications support AES and only AES tickets are generated, then it would be an excellent indicator to alert on event ID 4769. If the ticket options is set for RC4, that is, if RC4 tickets are generated in the AD environment (which is not the default configuration), then we should alert and follow up on it. 


### Honeypot

A honeypot user is a perfect detection option to configure in an AD environment; this must be a user with no real use/need in the environment, so no service tickets are generated regularly. In this case, any attempt to generate a service ticket for this account is likely malicious and worth inspecting. There are a few things to ensure when using this account:


  -  The account must be a relatively old user, ideally one that has become bogus (advanced threat actors will not request tickets for new accounts because they likely have strong passwords and the possibility of being a honeypot user).
  -  The password should not have been changed recently. A good target is 2+ years, ideally five or more. But the password must be strong enough that the threat agents cannot crack it.
  -  The account must have some privileges assigned to it; otherwise, obtaining a ticket for it won't be of interest (assuming that an advanced adversary obtains tickets only for interesting accounts/higher likelihood of cracking, e.g., due to an old password).
  -  The account must have an SPN registered, which appears legit. IIS and SQL accounts are good options because they are prevalent.


  
