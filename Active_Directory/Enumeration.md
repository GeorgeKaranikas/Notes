                ----External recon

    The table below highlights the "What" in what we would be searching for during this phase of our engagement.

    Data Point 	                    Description
IP Space 	                   Valid ASN for our target, netblocks in use for the organization's                public-facing infrastructure, cloud presence and the hosting                        providers, DNS record entries, etc.



Domain Information 	            Based on IP data, DNS, and site registrations.Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.)



Schema Format 	            Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc.


Data Disclosures 	        For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain intranet site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.)



Breach Data 	            Any publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold.






The table below lists a few potential resources and examples that can be used.


        Resource 	            Examples

ASN / IP registrars 	                IANA, arin for searching the Americas, RIPE for searching in Europe, BGP Toolkit

Domain Registrars & DNS 	            Domaintools, PTRArchive, ICANN, manual DNS record requests against the domain in question or against well known DNS servers, such as 8.8.8.8.

Social Media 	                        Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization.


Public-Facing Company Websites 	        Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines.

Cloud & Dev Storage Spaces 	            GitHub, AWS S3 buckets & Azure Blog storage containers, Google searches using "Dorks"

Breach Data Sources 	                HaveIBeenPwned to determine if any corporate email accounts appear in public breach data, Dehashed to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication.



        \\\\Finding Address Spaces

    The BGP-Toolkit hosted by Hurricane Electric is a fantastic resource for researching what address blocks are assigned to an organization and what ASN they reside within. Just punch in a domain or IP address, and the toolkit will search for any results it can. 



        \\\DNS

    DNS is a great way to validate our scope and find out about reachable hosts the customer did not disclose in their scoping document. Sites like domaintools, and viewdns.info are great spots to start. We can get back many records and other data ranging from DNS resolution to testing for DNSSEC and if the site is accessible in more restricted countries. Sometimes we may find additional hosts out of scope, but look interesting. In that case, we could bring this list to our client to see if any of them should indeed be included in the scope. We may also find interesting subdomains that were not listed in the scoping documents, but reside on in-scope IP addresses and therefore are fair game.


    This is also a great way to validate some of the data found from our IP/ASN searches. Not all information about the domain found will be current, and running checks that can validate what we see is always good practice.


        \\Public Data

    Social media can be a treasure trove of interesting data that can clue us in to how the organization is structured, what kind of equipment they operate, potential software and security implementations, their schema, and more. On top of that list are job-related sites like LinkedIn, Indeed.com, and Glassdoor. Simple job postings often reveal a lot about a company. 

    Websites hosted by the organization are also great places to dig for information. We can gather contact emails, phone numbers, organizational charts, published documents, etc. These sites, specifically the embedded documents, can often have links to internal infrastructure or intranet sites that you would not otherwise know about. Checking any publicly accessible information for those types of details can be quick wins when trying to formulate a picture of the domain structure. With the growing use of sites such as GitHub, AWS cloud storage, and other web-hosted platforms, data can also be leaked unintentionally


        \\\Hunting For Files

    google.com  --- filetype:pdf inurl:inlanefreight.com 


        \\\Hunting E-mail Addresses

    google.com --- intext:"@inlanefreight.com" inurl:inlanefreight.com

        \\E-mail Dork Results

    Browsing the contact page, we can see several emails for staff in different offices around the globe. We now have an idea of their email naming convention (first.last) and where some people work in the organization. This could be handy in later password spraying attacks or if social engineering/phishing were part of our engagement scope.

        \\Username Harvesting

    We can use a tool such as linkedin2username to scrape data from a company's LinkedIn page and create various mashups of usernames (flast, first.last, f.last, etc.) that can be added to our list of potential password spraying targets.

        \\Credential Hunting

    Dehashed is an excellent tool for hunting for cleartext credentials and password hashes in breach data. We can search either on the site or using a script that performs queries via the API. Typically we will find many old passwords for users that do not work on externally-facing portals that use AD auth (or internal), but we may get lucky! This is another tool that can be useful for creating a user list for external or internal password spraying.



                    -----Initial Enumeration of the Domain

    Our tasks to accomplish for this section are:

    Enumerate the internal network, identifying hosts, critical services, and potential avenues for a foothold.
    This can include active and passive measures to identify users, hosts, and vulnerabilities we may be able to take advantage of to further our access.
    
    Document any findings we come across for later use. Extremely important!

    We will start from our Linux attack host without domain user credentials.
    Below are some of the key data points that we should be looking for at this time and noting down into our notetaking tool of choice and saving scan/tool output to files whenever possible.

                        Key Data Points
    Data Point 	                                Description
    AD Users 	                    We are trying to enumerate valid user accounts we can target for password spraying.
    
    
    AD Joined Computers 	        Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc.
    
    Key Services 	                Kerberos, NetBIOS, LDAP, DNS
    
    Vulnerable Hosts and Services 	Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold)



            \\\\Tactics, techniques and procedures (TTPs)

    It is important to reproduce every example and even try to recreate examples with different tools to see how they work differently, learn their syntax, and find what approach works best for us.

    We will start with passive identification of any hosts in the network, followed by active validation of the results to find out more about each host (what services are running, names, potential vulnerabilities, etc.). Once we know what hosts exist, we can proceed with probing those hosts, looking for any interesting data we can glean from them. After we have accomplished these tasks, we should stop and regroup and look at what info we have. At this time, we'll hopefully have a set of credentials or a user account to target for a foothold onto a domain-joined host or have the ability to begin credentialed enumeration from our Linux attack host.



        ---> Identifying Hosts

    We can use Wireshark and TCPDump to "put our ear to the wire" and see what hosts and types of network traffic we can capture. This is particularly helpful if the assessment approach is "black box." We notice some ARP requests and replies, MDNS, and other basic layer two packets (since we are on a switched network, we are limited to the current broadcast domain) some of which we can see below. This is a great start that gives us a few bits of information about the customer's network setup.


    !!  If we are on a host without a GUI (which is typical), we can use tcpdump, net-creds, and NetMiner, etc., to perform the same functions. We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.


    There is no one right way to listen and capture network traffic. There are plenty of tools that can process network data. Wireshark and tcpdump are just a few of the easiest to use and most widely known. Depending on the host you are on, you may already have a network monitoring tool built-in, such as pktmon.exe, which was added to all editions of Windows 10. As a note for testing, it's always a good idea to save the PCAP traffic you capture. You can review it again later to look for more hints, and it makes for great additional information to include while writing your reports.

    Our first look at network traffic pointed us to a couple of hosts via MDNS and ARP. Now let's utilize a tool called Responder to analyze network traffic and determine if anything else in the domain pops up.

    Responder is a tool built to listen, analyze, and poison LLMNR, NBT-NS, and MDNS requests and responses. It has many more functions, but for now, all we are utilizing is the tool in its Analyze mode. This will passively listen to the network and not send any poisoned packets. We'll cover this tool more in-depth in later sections.

            ---->Responder

    
    $ sudo responder -I ens224 -A 
                        ^
                        |
                        |
                select the interface


    As we start Responder with passive analysis mode enabled, we will see requests flow in our session. Notice below that we found a few unique hosts not previously mentioned in our Wireshark captures. It's worth noting these down as we are starting to build a nice target list of IPs and DNS hostnames.


    Our passive checks have given us a few hosts to note down for a more in-depth enumeration. Now let's perform some active checks starting with a quick ICMP sweep of the subnet using fping.

        ----> fping

    Fping provides us with a similar capability as the standard ping application in that it utilizes ICMP requests and replies to reach out and interact with a host. Where fping shines is in its ability to issue ICMP packets against a list of multiple hosts at once and its scriptability. Also, it works in a round-robin fashion, querying hosts in a cyclical manner instead of waiting for multiple requests to a single host to return before moving on. These checks will help us determine if anything else is active on the internal network. ICMP is not a one-stop-shop, but it is an easy way to get an initial idea of what exists. Other open ports and active protocols may point to new hosts for later targeting. 

    \\\FPing Active Checks

    Here we'll start fping with a few flags: a to show targets that are alive, s to print stats at the end of the scan, g to generate a target list from the CIDR network, and q to not show per-target results.

    $ fping -asgq 172.16.5.0/23



    \\\\Nmap Scanning

    Now that we have a list of active hosts within our network, we can enumerate those hosts further. We are looking to determine what services each host is running, identify critical hosts such as Domain Controllers and web servers, and identify potentially vulnerable hosts to probe later. With our focus on AD, after doing a broad sweep, it would be wise of us to focus on standard protocols typically seen accompanying AD services, such as DNS, SMB, LDAP, and Kerberos name a few. Below is a quick example of a simple Nmap scan.

    $sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum




                -----Identifying Users

    \\\Kerbrute - Internal AD Username Enumeration


    Kerbrute can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts. We will use Kerbrute in conjunction with the jsmith.txt or jsmith2.txt user lists from Insidetrust. This repository contains many different user lists that can be extremely useful when attempting to enumerate users when starting from an unauthenticated perspective. We can point Kerbrute at the DC we found earlier and feed it a wordlist. The tool is quick, and we will be provided with results letting us know if the accounts found are valid or not, which is a great starting point for launching attacks such as password spraying, which we will cover in-depth later in this module.



    To get started with Kerbrute, we can download precompiled binaries for the tool for testing from Linux, Windows, and Mac, or we can compile it ourselves. This is generally the best practice for any tool we introduce into a client environment. To compile the binaries to use on the system of our choosing, we first clone the repo:


    $ sudo git clone https://github.com/ropnop/kerbrute.git

    Typing make help will show us the compiling options available.

    $ sudo make all


    $ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users





                -----Identifying Potential Vulnerabilities

    The local system account NT AUTHORITY\SYSTEM is a built-in account in Windows operating systems. It has the highest level of access in the OS and is used to run most Windows services. It is also very common for third-party services to run in the context of this account by default. A SYSTEM account on a domain-joined host will be able to enumerate Active Directory by impersonating the computer account, which is essentially just another kind of user account. Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.


    There are several ways to gain SYSTEM-level access on a host, including but not limited to:

    Remote Windows exploits such as MS08-067, EternalBlue, or BlueKeep.
    
    Abusing a service running in the context of the SYSTEM account, or abusing the service account SeImpersonate privileges using Juicy Potato. This type of attack is possible on older Windows OS' but not always possible with Windows Server 2019.
    
    Local privilege escalation flaws in Windows operating systems such as the Windows 10 Task Scheduler 0-day.
    
    Gaining admin access on a domain-joined host with a local account and using Psexec to launch a SYSTEM cmd window



    By gaining SYSTEM-level access on a domain-joined host, you will be able to perform actions such as, but not limited to:

    Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
    Perform Kerberoasting / ASREPRoasting attacks within the same domain.
    Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
    Perform token impersonation to hijack a privileged domain user account.
    Carry out ACL attacks.



    

