# Enable gMSA (Group Managed Service Accounts)

### Requirements 

- You must create a KDS root key on a domain controller in the domain.

```
PS > Add-KdsRootKey –EffectiveImmediately

```

### Create new Group

```
PS > New-ADServiceAccount -Name {groupName} -PrincipalsAllowedToRetrieveManagedPassword {ServiceAcc1,ServiceAcc2,...}

```

# DNS Server Setup

### Manage DNS zones with Powershell




|Cmdlet |	Description|
|--------|--------------|
Add-DnsServerPrimaryZone 	|Create a primary DNS zone
Add-DnsServerSecondaryZone |	Create a secondary DNS zone
Get-DnsServerZone 	|View configuration information for a DNS zone
Get-DnsServerZoneAging 	|View aging configuration for a DNS zone
Remove-DnsServerZone |	Removes a DNS zone
Restore-DnsServerPrimaryZone |	Reloads the zone content from AD DS or a zone file
Set-DnsServerPrimaryZone |	Modifies the settings of a primary DNS zone
Start-DnsServerZoneTransfer |	Triggers a zone transfer to a secondary DNS zone

` Needs DNSServer module installed`


### Create DNS resource records with Powershell


|Cmdlet 	|Description|
|-----------|-----------|
Add-DnsServerResourceRecord 	|Creates any resource record, specified by type
Add-DnsServerResourceRecordA 	|Creates a host (A) resource record
Add-DnsServerResourceRecordAAAA 	|Creates a host (AAAA) resource record
Add-DnsServerResourceRecordCNAME |	Creates a CNAME alias resource record
Add-DnsServerResourceRecordMX |	Creates an MX resource record
Add-DnsServerResourceRecordPtr |	Creates a PTR resource record


# Create Self-Signed Cert

```
New-SelfSignedCertificate -DnsName  "www.domainname.com" -CertStoreLocation "cert:\LocalMachine\My"

```