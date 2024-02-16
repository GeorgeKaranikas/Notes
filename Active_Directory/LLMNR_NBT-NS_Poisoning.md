    Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port 5355 over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port 137 over UDP.


    The kicker here is that when LLMNR/NBT-NS are used for name resolution, ANY host on the network can reply. This is where we come in with Responder to poison these requests. With network access, we can spoof an authoritative name resolution source ( in this case, a host that's supposed to belong in the network segment ) in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host. This poisoning effort is done to get the victims to communicate with our system by pretending that our rogue system knows the location of the requested host. If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain. SMB Relay attacks will be covered in a later module about Lateral Movement.


    \\Example - LLMNR/NBT-NS Poisoning


    A host attempts to connect to the print server at \\print01.inlanefreight.local, but accidentally types in \\printer01.inlanefreight.local.
   
    The DNS server responds, stating that this host is unknown.
    
    The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.inlanefreight.local.
    
    The attacker (us with Responder running) responds to the host stating that it is the \\printer01.inlanefreight.local that the host is looking for.
   
    The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
    
    This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.


    Several tools can be used to attempt LLMNR & NBT-NS poisoning:
    Tool 	        Description
Responder 	        Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.

Inveigh 	        Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.

Metasploit      	Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.


            \\\\\\Responder
    $ responer -I {interface}


--- >  the -A flag puts us into analyze mode, allowing us to see NBT-NS, BROWSER, and LLMNR requests in the environment without poisoning any responses. 

--- > -w this will start the WPAD rogue proxy server.will capture all HTTP requests by any users that launch Internet Explorer if the browser has Auto-detect settings enabled.On old Windows systems (i.e. lacking the MS16-077 security update), the WPAD location could be obtained through insecure name resolution protocols like LLMNR and NBT-NS when standard DNS queries were failing (i.e. no DNS record for WPAD).

--- > -f  will attempt to fingerprint the remote host operating system and version

--- > -v flag for increased verbosity

--- > -F and -P can be used to force NTLM or Basic authentication and force proxy authentication

 If you are successful and manage to capture a hash, Responder will print it out on screen and write it to a log file per host located in the /usr/share/responder/logs directory. 

 Hashes are saved in the format (MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt

 e.g  SMB-NTLMv2-SSP-172.16.5.25.txt

 Hashes are also stored in a SQLite database that can be configured in the Responder.conf config file, typically located in /usr/share/responder unless we clone the Responder repo directly from GitHub.


    !! make sure these ports are available in your attack host in order for the script to function at it`s best.

UDP 137, UDP 138, UDP 53, UDP/TCP 389,TCP 1433, UDP 1434, TCP 80, TCP 135, TCP 139, TCP 445, TCP 21, TCP 3141,TCP 25, TCP 110, TCP 587, TCP 3128, Multicast UDP 5355 and 5353

Any of the rogue servers (i.e., SMB) can be disabled in the Responder.conf file.


Typically we should start Responder and let it run for a while in a tmux window while we perform other enumeration tasks to maximize the number of hashes that we can obtain. Once we are ready, we can pass these hashes to Hashcat using hash mode 5600 for NTLMv2 hashes that we typically obtain with Responder.




            \\\\Inveigh

 Inveigh works similar to Responder, but is written in PowerShell and C#. Inveigh can listen to IPv4 and IPv6 and several other protocols, including LLMNR, DNS, mDNS, NBNS, DHCPv6, ICMPv6, HTTP, HTTPS, SMB, LDAP, WebDAV, and Proxy Auth. The tool is available in the C:\Tools directory on the provided Windows attack host.



    There is a wiki that lists all parameters and usage instructions.

    https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters


PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters

Let's start Inveigh with LLMNR and NBNS spoofing, and output to the console and write to a file. We will leave the rest of the defaults, which can be seen here.

-->  https://github.com/Kevin-Robertson/Inveigh#parameter-help

PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y



        \\\C# Inveigh (InveighZero)

The PowerShell version of Inveigh is the original version and is no longer updated. The tool author maintains the C# version, which combines the original PoC C# code and a C# port of most of the code from the PowerShell version. Before we can use the C# version of the tool, we have to compile the executable. To save time, we have included a copy of both the PowerShell and compiled executable version of the tool in the C:\Tools folder on the target host in the lab, but it is worth walking through the exercise (and best practice) of compiling it yourself using Visual Studio.

Let's go ahead and run the C# version with the defaults and start capturing hashes.

PS C:\htb> .\Inveigh.exe

As we can see, the tool starts and shows which options are enabled by default and which are not. The options with a [+] are default and enabled by default and the ones with a [ ] before them are disabled. The running console output also shows us which options are disabled and, therefore, responses are not being sent (mDNS in the above example). We can also see the message Press ESC to enter/exit interactive console, which is very useful while running the tool. The console gives us access to captured credentials/hashes, allows us to stop Inveigh, and more.

We can hit the esc key to enter the console while Inveigh is running.

After typing HELP and hitting enter, we are presented with several options.

We can quickly view unique captured hashes by typing GET NTLMV2UNIQUE.

We can type in GET NTLMV2USERNAMES and see which usernames we have collected. This is helpful if we want a listing of users to perform additional enumeration against and see which are worth attempting to crack offline using Hashcat.