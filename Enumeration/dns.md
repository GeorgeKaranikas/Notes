- UDP Port 53 for DNS Request`s
- TCP Port 53 for DNS Zone Transfering


# DNS records

|DNS Record 	|        Description|
|-------|-------|
A 	       |     Returns an IPv4 address of the requested domain as a result.
AAAA 	  |      Returns an IPv6 address of the requested domain.
MX 	     |       Returns the responsible mail servers as a result.
NS 	            Returns the DNS servers (nameservers) of the domain.

TXT 	      |  This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam.
CNAME 	      |   This record serves as an alias. If the domain www.hackthebox.eu should point to the same IP, and we create an A record for one and a CNAME record for the other.
PTR 	   |     The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.
SOA 	     |   Provides information about the corresponding DNS zone and email address of the administrative contact.



# Bind Zone file Format

- at least one NS record
- There must be precisely one SOA record and at least one NS record.
- A zone file describes a zone completely.

A zone file is a text file that describes a DNS zone with the BIND file format. In other words it is a point of delegation in the DNS tree. . A syntax error usually results in the entire zone file being considered unusable. The name server behaves similarly as if this zone did not exist. It responds to DNS queries with a SERVFAIL error message.


For the IP address to be resolved from the Fully Qualified Domain Name (FQDN), the DNS server must have a reverse lookup file. In this file, the computer name (FQDN) is assigned to the last octet of an IP address, which corresponds to the respective host, using a PTR record. The PTR records are responsible for the reverse translation of IP addresses into names, as we have already seen in the above table.

[common DNS attacks](https://securitytrails.com/blog/most-popular-types-dns-attacks)

# Footprinting

So, first of all, the DNS server can be queried as to which other name servers are known.We do this using the NS record and the specification of the DNS server we want to query using the @ character. 
This is because if there are other DNS servers, we can also use them and query the records. However, other DNS servers may be configured differently and, in addition, may be permanent for other zones.

`$ dig ns {domain} @{dns_server}`


### Chaos request

Sometimes it is also possible to query a DNS server's version using a class CHAOS query and type TXT. However, this entry must exist on the DNS server. 

`$ dig CH TXT version.bind {dns_server}`



    ! We can use the option ANY to view all available records
    However newer server do not respond to any and we have to
    query available records manually.



# zone transfer

Zone transfer refers to the transfer of zones to another server in DNS, which generally happens over TCP port 53. This procedure is abbreviated Asynchronous Full Transfer Zone (AXFR). Since a DNS failure usually has severe consequences for a company, the zone file is almost invariably kept identical on several name servers. When changes are made, it must be ensured that all servers have the same data. Synchronization between the servers involved is realized by zone transfer. Using a secret key rndc-key, which we have seen initially in the default configuration, the servers make sure that they communicate with their own master or slave.


`$ dig axfr {domain} @{primary_dns_server}`


        !If the administrator used a subnet for the allow-transfer option for testing purposes or as a workaround solution or set it to any, everyone would query the entire zone file at the DNS server.

# Bruteforcing A records

```
$ for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.{domain} @{dns_server} | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```


# dnsenum

```
$ dnsenum --dnsserver {dns_server} --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt {domaim}
```

    