- tcp port 3306

# Default Configuration File
    
`$ cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'`

# Dangerous Settings

            
|Settings 	   |     Description|
|-------------|---------|
user 	           |     Sets which user the MySQL service will run as.
password 	       |     Sets the password for the MySQL user.
admin_address 	      |  The IP address on which to listen for TCP/IP connections on the 
administrative network interface.
debug 	     |           This variable indicates the current debugging settings
sql_warnings 	      |  This variable controls whether single-row INSERT statements produce an 
information string if warnings occur.
secure_file_priv 	|   This variable is used to limit the effect of data import and export operations.


The settings user, password, and admin_address are security-relevant because the entries are made in plain text. Often, the rights for the configuration file of the MySQL server are not assigned correctly. If we get another way to read files or even a shell, we can see the file and the username and password for the MySQL server. Suppose there are no other security measures to prevent unauthorized access. In that case, the entire database and all the existing customers information, email addresses, passwords, and personal data can be viewed and even edited.


The debug and sql_warnings settings provide verbose information output in case of errors, which are essential for the administrator but should not be seen by others. This information often contains sensitive content, which could be detected by trial and error to identify further attack possibilities. These error messages are often displayed directly on web applications. Accordingly, the SQL injections could be manipulated even to have the MySQL server execute system commands. 


# Footprinting the Service

`$ sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*`

        
# Interaction with the MySQL Server
        
`$ mysql -u {user} -p {password} -h x.x.x.x`


# Usefull commands

|Command 	                |                        Description|
|--------------------|-------------------|
mysql -u <user> -p<password> -h <IP address> 	        Connect to the MySQL server. There should not be a space between the '-p' flag, and the password.
show databases; 	             |                    Show all databases.
use <database>; 	                |                 Select one of the existing databases.
show tables; 	                        |                Show all available tables in the selected database.
show columns from <table>; 	         |               Show all columns in the selected database.
select * from <table>; 	                 |               Show everything in the desired table.
select * from <table> where <column> = "<string>"; 	|Search for needed string in the desired table.












