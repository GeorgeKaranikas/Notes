SPN scanning performs service discovery via LDAP queries to a Domain Controller. Since SPN queries are part of normal Kerberos ticket behavior, it is difficult, if not infeasible to detect, while netowkr port scanning is pretty obvious.


An SPN is a string of the following format.
SPN = serviceclass “/” hostname [“:”port] [“/” servicename]

serviceclass is a string that identifies the class of the service, such as “www” for a Web service or “ldap” for a directory service.
hostname ([RFC2396] section 3.2.2) is a string that is the name of the system. This SHOULD be the fully qualified domain name (FQDN).
port ([RFC2396] section 3.2.2) is a number that is the port number for the service.

Interestingly enough, SPNs are queried almost constantly in an Active Directory environment all the time as clients request access to services. Furthermore, since the servicePrincipalName attribute is indexed in Active Directory, the results are usually returned in under a second.

ADForestInfoRootDomain = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).RootDomain

        
        $ADForestInfoRootDomainDN = “DC=” + $ADForestInfoRootDomain -Replace(“\.”,’,DC=’)

        $ADDomainInfoLGCDN = ‘GC://’ + $ADForestInfoRootDomainDN

        $root = [ADSI]$ADDomainInfoLGCDN

        $ADSPNSearcher = new-Object System.DirectoryServices.DirectorySearcher($root,”(serviceprincipalname=*sql*)”)

        $ADSPNSearcher.PageSize = 500

        $AllADSQLServerSPNs = $ADSPNSearcher.FindAll()







