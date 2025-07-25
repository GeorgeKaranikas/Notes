- PORT 139/445 (NetBIOS/SMB)



- We know that Samba is suitable for both Linux and Windows systems. In a network, each host participates in the same workgroup. A workgroup is a group name that identifies an arbitrary collection of computers and their resources on an SMB network.


## Samba configuration file

        $  cat /etc/samba/smb.conf



## Common Setings


    |Setting 	          |                  Description|
|-------------------------|-------------------------------|
[sharename] 	                |The name of the network share.
workgroup = WORKGROUP/DOMAIN 	|Workgroup that will appear when clients query.
path = /path/here/ 	           | The directory to which user is to be given access.
server string = STRING 	       | The string that will show up when a connection is initiated.
unix password sync = yes 	 |   Synchronize the UNIX password with the SMB password?
usershare allow guests = yes |	Allow non-authenticated users to access defined shared?
map to guest = bad user 	 |   What to do when a user login request doesn't match a valid UNIX user?
browseable = yes 	         |   Should this share be shown in the list of available shares?
guest ok = yes 	              |  Allow connecting to the service without using a password?
read only = yes 	        |    Allow users to read files only?
create mask = 0700 	        |    What permissions need to be set for newly created files

# Dangerous Settings

  | Setting 	                    |        Description|
|------------------------|-----------------------------|
browseable = yes 	  |          Allow listing available shares in the current share?
read only = no 	       |         Forbid the creation and modification of files?
writable = yes 	        |        Allow users to create and modify files?
guest ok = yes 	         |       Allow connecting to the service without using a password?
enable privileges = yes |	    Honor privileges assigned to specific SID?
create mask = 0777 	     |       What permissions must be assigned to the newly created files?
directory mask = 0777 	  |      What permissions must be assigned to the newly created directories?
logon script = script.sh 	|    What script needs to be executed on the user's login?
magic script = script.sh 	 |   Which script should be executed when the script gets closed?
magic output = script.out 	  |  Where the output of the magic script needs to be stored?


# Work with smbclient
- Now we can display a list (-L) of the server's shares with the smbclient command from our host. We use the so-called null session (-N), which is anonymous access without the input of existing users or valid passwords.

`$ smbclient -N -L //x.x.x.x`

- you can always try the guest account
    


### accessing the share

```

$ smbclient //x.x.x.x/{share}
$ smbclient ////x.x.x.x//{share}
$ smbclient \\\\x.x.x.x\\{share}
```

Smbclient also allows us to execute local system commands using an exclamation mark at the beginning (!<cmd>) without interrupting the connection.

```
smb: \> !cat file.txt
```


# Enum with nmap

`$sudo nmap x.x.x.x -sV -sC -p139,445`

    
# enum with rpcclient on a Null Session 


|Query| 	Description|
|-------|--------|
srvinfo 	|Server information.
enumdomains 	|Enumerate all domains that are deployed in the network.
querydominfo 	|Provides domain, server, and user information of deployed domains.
netshareenumall |	Enumerates all available shares.
netsharegetinfo <share> 	|Provides information about a specific share.
enumdomusers 	|Enumerates all domain users.
queryuser <RID> |	Provides information about a specific user.


```
$rpcclient -U "" x.x.x.x
    (NULL SESSION)

rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> queryhroup {rid}  #query Group Information and Group Membership
```

Before password spraying, it is very useful to determine the Windows domain password policy using a command such as “NET ACCOUNTS /DOMAIN” in the Windows world. 

rpcclient $>  getdompwinfo
                

# RID BruteForcing bash script

```
$ for i in $(seq 500 1100);do rpcclient -N -U "" xx.xx.xx.xx -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```


# enum users using impacket
        
`$ samrdump.py x.x.x.x`


# enum shares using smbmap
        
`$ smbmap -H x.x.x.x

    
# enum shares using crackmapexec

```
$ crackmapexec smb x.x.x.x --shares -u '' -p '' (NULL Session)
$ crackmapexec SMB <IP> -u USER -p PASSWORD --spider C\$ --pattern txt
```

# List all readable files

`crackmapexec smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus`

# Enum4Linux-ng

```

$ git clone https://github.com/cddmp/enum4linux-ng.git
$ cd enum4linux-ng
$ pip3 install -r requirements.txt

```


`$ ./enum4linux-ng.py 10.129.14.128 -A`

    