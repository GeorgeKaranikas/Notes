#  the default Linux-based firewall software
[Linux iptables Pocket Reference](https://linuxbg.eu/books/Linux%20Iptables%20Pocket%20Reference.pdf)

[In depth Guide](https://www.booleanworld.com/depth-guide-iptables-linux-firewall/)

[Extensions and modules](https://ipset.netfilter.org/iptables-extensions.man.html)

iptables is, usually,by default installed on most linux operating systems so its essentiall to be able to configure your system and its routing rules.

# Definitions 

##  Chain

A chain is basically a set of rules and is a subset of tables.The three builtin chains are INPUT,OUTPUT and FORWARD in the filter table, which is the default table if no option set with **-t** .

` -L [chain]` : Lists a chain in the specified table

`-A [chain] ` :append a rule to the specified table with -t [table].

`-C [chain]` : check a rule in the specified chain and table.

`-D [chain]` : Delete a rule in the specified chain.

`-F [chain]` : Flush all rules in the specified chain.



- PREROUTING : traffic might be in the NIC and just arived in the machine.Present on nat,mangle and raw tables

- INPUT : traffic inbound from outside to this host

- FORWARD : traffic that uses this host as a router

- OUTPUT : traffic that this host wants to send out

- POSTROUTING : present in nat and mangle tables

`!  By default, all chains have a default policy of allowing packets.`

## Tables

Several different tables may be defined.  Each table contains a number of built-in chains and may also contain user-defined chains.

- filter : the default table if not otherwise set.

- nat : operates in header values of destination and source addresses and enforces Network Address protocol like operations.

- mangle : it is being used for operations appropriate for a routing device like changing header values,flags etc.

- security: This table is used for Mandatory Access Control (MAC) networking rules, such as those enabled by the SECMARK and CONNSECMARK targets.

- raw : operate to the packet before the kernel processes it.(you cant be aware of its state though)

## --ctstate option

The state of the connection can be:

- NEW: represents the first packet of a connection.

- ESTABLISHED: used for packets that are part of an existing connection.

- RELATED: This state is used for connections that are related to another ESTABLISHED connection. An example of this is a FTP data connection — they’re “related” to the already “established” control connection.

- INVALID: This state means the packet doesn’t have a proper state.

- UNTRACKED

- DNAT : destination modified by nat table

- SNAT:  source modified by nat


## Targets

the --jump (-j in short terms) option set the target ,meaning the operation enforced on the packet.

Might be a terminating target like ACCCEPT,DROP,FORWARD , as if the rule is matched , the proccess of iterating in the chain is over.

There are also NON-Terminating targets like log where iptables keeps examining the chain rules for the packet.

# Listing existing rules

- This command lists the rules 'like' the command used to configure the rule

```
$ sudo iptables -S
```


- Listing table-view

```
$ sudo iptables -L [table] --line-numbers
```

if no table specified all tables are shown (INPUT , OUTPUT , FORWARD)

# Delete Rules

- Delete all rules in all chains

```
$ sudo iptables -F 
```

- Delete all rules in a chain

```
$ sudo iptables -F [chain]
```

- If you want to delete rules using this method, you can use the output of the rules list. The -A option, which is used to indicate the rule position at creation time, should be excluded here.

```
$ sudo iptables -S

$ sudo iptables -D ' the command without -A'

```

### Deleting Rules by Chain and Number

- list the rules in the table format and add the --line-numbers option, and once you know the rule and run the iptables -D command followed by the chain and rule number

```
$ sudo iptables -L --line-numbers

$ sudo iptables -D [chain] [line number]
```

# Modifying Default Policy of a chain

```
$ iptables  --policy INPUT DROP
```

# Inserting a Rule in a specific line

```
$ sudo iptables -I INPUT [line] -s {ip/subnet} -j ACCEPT
```
# Allow all traffic

You can flush all chains , tables and rules in order to reconfigure your firewall all over again.


### Step 1 

- ensure you will not be locked out if you've accessed the host remotely

- -P : Change policy on chain to target

```
$  sudo iptables -P INPUT ACCEPT

$  sudo iptables -P FORWARD ACCEPT

$  sudo iptables -P OUTPUT ACCEPT
```

### Step 2

- flush the nat and mangle tables, flush all chains (-F), and delete all non-default chains


```
$ sudo iptables -t nat -F

$ sudo iptables -t mangle -F

$ sudo iptables -F

$ sudo iptables -X
```


# Allow loopback connections

```
$ sudo iptables -A INPUT -i lo -j ACCEPT
$ sudo iptables -A FORWARD -i lo -j ACCEPT
$ sudo iptables -A OUTPUT -i lo -j ACCEPT
```


# Allow enstablished connections

```
$ sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

$ sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

# Allowing/Disallowing Internal Network to access External

```
$ sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT/DROP
```

# Block an IP

```
$ sudo iptables -A INPUT -s {ip} -j DROP
```
- If you want to reject the connection instead, which will respond to the connection request with a “connection refused” error
```
$ sudo iptables -A INPUT -s {ip} -j REJECT
```

# Allow incoming ssh connection

```
$ sudo iptables -A INPUT -p tcp [-s ip/subnet] --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT


$ sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```
- The second command, which allows the outgoing traffic of established SSH connections, is only necessary if the OUTPUT policy is not set to ACCEPT.

# Allow outgoing ssh traffic

- If your firewall OUTPUT policy is not set to ACCEPT

```
$ sudo iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

$ sudo iptables -A INPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT


```

# Negating conditions

- Allow only HTTP,HTTPS and SSH traffic

```
$ sudo iptables -A INPUT -p tcp -m multiport ! --dports 22,80,443 -j DROP
```

# Block Nmap (and scanning)

### Xmass scanning
! [xmass](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) scanning sets fin,psh,and urg flags

- The tcp module has a --tcp-flags switch, and you can use it to check individual TCP flags. This switch takes in two arguments: a mask and a set of compared flags. 

```
$ sudo iptables --append INPUT --protocol tcp --match tcp --tcp-flags ALL FIN,PSH,URG --jump DROP
```


### Port scanning

Port scanners might not scan with tcp normal behaviour like a SYN,SYN-ACK,ACK order.

So you can block packets not tracked by a connection but also not a SYN packet.

you simply need to check the FIN, RST, ACK and SYN flags(thats the mask) however only SYN should be set(thats the compared flags)

```
$ sudo iptables -A INPUT -p tcp --match conntrack --ctstate NEW --match tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j DROP
```

# Rate limmitng

### Change default policy for pings

```
$ sudo iptables -A INPUT -p icmp  --match limit --limit 1/sec --limit-burst 1 -j ACCEPT 
```

### Rate limmiting ssh connections

[recent module](https://ipset.netfilter.org/iptables-extensions.man.html)

- --name [name]:
    Specify the list to use for the commands. If no name is given then DEFAULT will be used.
- [!] --set:
    This will add the source address of the packet to the list. If the source address is already in the list, this will update the existing entry. This will always return success (or failure if ! is passed in). 
- --rsource :
    Match/save the source address of each packet in the recent list table.
```
$ sudo iptables -A INPUT -p tcp -m tcp 
--dport 22 -m conntrack --ctstate NEW -m recent --set --name SSHLIMIT  --rsource

$ sudo iptables -A INPUT -p tcp -m tcp 
--dport 22 -m conntrack --ctstate NEW -m recent --set --name SSHLIMIT --update --seconds 180 --hitcount 5 --name SSH --rsource --jump DROP
```
- --update : Check the source address and the "last seen" timestamp if it matches.
   `!  the --set also counts as one additional hit if the list already exists. It does not reset the list. In other words, the --set nearly works like the --update except that it has the ability to create the list.`
- --seconds [seconds] :
    This option must be used in conjunction with one of --rcheck or --update. When used, this will narrow the match to only happen when the address is in the list and was seen within the last given number of seconds. 
- --hitcount [hits] :
    This option must be used in conjunction with one of --rcheck or --update. When used, this will narrow the match to only happen when the address is in the list and packets had been received greater than or equal to the given value. This option may be used along with --seconds to create an even narrower match requiring a certain number of hits within a specific time frame. ***MAX = 20***

### Syn-flooding

[post](https://linux.m2osw.com/create-rules-protect-you-syn-flood-attack)

```
$ iptables -A INPUT -m recent --rcheck --name synflood --seconds 60 --reap

$ iptables -A INPUT -p tcp \              # chain / protocol
    -m tcp --syn \                      # user is trying to connect with TCP?
    -m recent --set --name synflood \   # create list or +1 hit
    -m recent --rcheck --seconds 60 --hitcount 100 \
    -j DROP                  # action if --rcheck true
```

# Port redirection

```
$ sudo iptables --table nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to 8080
```

# Port Forwardning 
[Youtube](https://www.youtube.com/watch?v=NAdJojxENEU)

# Custom Chains

- Create the chain 

``` 
$ sudo iptables -N ssh-rules
```

- Config the chain

```
$ sudo iptables -A INPUT -p tcp -m tcp --dport 22 -s [subnet] -j ACCEPT

$ sudo iptables -A INPUT -p tcp -m tcp --dport 22 -s [subnet2] -j DROP
```
- add RETURN for a non terminating chain

```
$ sudo iptables -A INPUT -p tcp -m tcp --dport 22 -j RETURN
```

- Refer the chain as a target

```
$ sudo iptables -A INPUT -p tcp -m tcp --dport 22 -j ssh-rules
```

- Delete the chain

! remember to first alter all the rules refering to the chain

```
$sudo iptables -X ssh-rules
```


# Examples 


### Redirect public_iface:port1 -> localhost:port2

```
# enables forwarding output traffic from eth0 to 1234/tcp to 127.0.0.1:32400 tcp

iptables -t nat -I PREROUTING -i eth0 -p tcp --dport 1234 -j DNAT --to 127.0.0.1:32400
iptables -I FORWARD -i lo -p tcp -d 127.0.0.1 --dport 32400 -j ACCEPT

# let the kernel accept public IPs accessing loopback interface
echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
```


# Defend NMAP scans

! Some firewalls try to prevent incoming TCP connections (while allowing outbound ones) by blocking any TCP packets with the **SYN** bit set and **ACK** cleared. Iptables firewall command offers a special --syn option to implement it.



#### Purpose of the scans

Scan through stateless firewall or ACL filters as such filters are configured to block access to ports usually by preventing SYN packets, thus stopping any attempt to 'build' a connection.

#### Disvantages

One cannot distinguish an open port from a filtered port analyzing this scan results.

`! Some systems ,like Windows and Cisco devices, send RST responses to the probes regardless of whether the port is open or not. This scan does work against most Unix-based systems though. `

