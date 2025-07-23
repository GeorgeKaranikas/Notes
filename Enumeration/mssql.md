- tcp port 1433


Microsoft SQL (MSSQL) is Microsoft's SQL-based relational database management system. Unlike MySQL, which we discussed in the last section, MSSQL is closed source and was initially written to run on Windows operating systems. It is popular among database administrators and developers when building applications that run on Microsoft's .NET framework due to its strong native support for .NET. There are versions of MSSQL that will run on Linux and MacOS, but we will more likely come across MSSQL instances on targets running Windows.



# Interact tools
-    mssql-cli 	
-   SQL Server 
-    PowerShell 	
-    HediSQL 	
-   SQLPro 	
-    Impacket's mssqlclient.py


# Default MSSQL Databases



|Default System Database 	|                    Description|
|-----------------------------|------------------------------|
master 	                  |  Tracks all system information for an SQL server instance
model 	                |    Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database
msdb 	                |    The SQL Server Agent uses this database to schedule jobs & alerts
tempdb 	               |     Stores temporary objects
resource 	           |     Read-only database containing system objects included with SQL server


# Default Configuration

We may benefit from looking into the following:

-    MSSQL clients not using encryption to connect to the MSSQL server

-    The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates

-   The use of named pipes

-    Weak & default sa credentials. Admins may forget to disable this account


# Footprinting the Service


`$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 x.x.x.x`

# Connecting with Mssqlclient.py

`$ python3 mssqlclient.py Administrator@x.x.x.x -windows-auth`


# Footprinting using metasploit

        
- searching for the mssql server through the network

```
        msfconsole> use auxiliary/scanner/mssql/mssql_ping
        msfconsole> set rhosts 10.10.10.1/24
```

- dictionary attack against mssql

```
msfconsole> use auxiliary/scanner/mssql/mssql_login
```

### while having credentials

- to enum  the schema with credentials

```        
use scanner/mssql/mssql_schemadump 
```

- enumeration script
        
```        
use auxiliary/admin/mssql/mssql_enum
```
- dumping the database

```
use auxiliary/scanner/mssql/mssql_schemadump
```

- executing commands using the xp_cmdshell

```
        use exploit/windows/mssql/mssql_payload
```        

- escalating privs using the sysadmin role
       
```       
        use auxiliary/admin/mssql/mssql_escalate_dbowner
```
- escalating privs with impersonation
  
```  
        use auxiliary/admin/mssql/mssql_escalate_execute_as
```        
