

- TCP Port 21 :connection enstablishment and commands
- TCP Port 20 : data tranfering

## Active FTP Connection


-    The client sends the PORT command to an FTP server. The source port is a random, high-numbered port. The destination port is 21.

-    The server responds with an ACK.

-    The server initiates a connection to the client with source port 20 and the destination port specified in the client’s PORT command.
-    The client sends an ACK to the server.  The FTP session has now been established.

## Passive FTP Conection




-    The client sends the PASV command to an FTP server on port 21. The source port is a random, high-numbered port. The destination port is 21.

-    The server responds with the PORT command. The port command specifies a random, high-numbered (ephemeral) port that the client can connect to.

-    The client initiates a connection to the server on this ephemeral port.

-    The server responds with an ACK. The FTP session has now been established



## TFTP

- UDP Port 69

Trivial File Transfer Protocol (TFTP) is simpler than FTP and performs file transfers between client and server processes. However, it does not provide user authentication and other valuable features supported by FTP.

|Commands 	|Description|
|-----------|---------|
connect 	|Sets the remote host, and optionally the port, for file transfers.
get |	Transfers a file or set of files from the remote host to the local host.
put |	Transfers a file or set of files from the local host onto the remote host.
quit 	|Exits tftp.
status |	Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on.
verbose |	Turns verbose mode, which displays additional information during file transfer, on or off.



## vsftpd server 

- The configuration of a vsftpd server is found in : /etc/vsftpd.conf 
                         


|Setting 	|Description|
|----------|--------------|
listen=NO |	    Run from inetd or as a standalone daemon?
listen_ipv6=YES |	                                    Listen on IPv6 ?
anonymous_enable=NO |	                                Enable Anonymous access?
local_enable=YES |	                                    Allow local users to login?
dirmessage_enable=YES |	                                Display active directory messages when users go into certain directories?
use_localtime=YES 	|                                    Use local time?
xferlog_enable=YES 	|                                    Activate logging of uploads/downloads?
connect_from_port_20=YES |	                            Connect from port 20?
secure_chroot_dir=/var/run/vsftpd/empty 	        |    Name of an empty directory
pam_service_name=vsftpd 	   |                         This string is the name of the PAM service vsftpd will use.
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem 	   | The last three options specify the location of the RSA certificate to use for SSL encrypted connections.
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key 	|
ssl_enable=NO 	|
dirmessage_enable=YES 	  |                              Show a message when they first enter a new directory?
chown_uploads=YES 	       |                             Change ownership of anonymously uploaded files?
chown_username=username 	|                            User who is given ownership of anonymously uploaded files.
local_enable=YES 	   |                                 Enable local users to login?
chroot_local_user=YES 	|                                Place local users into their home directory?
chroot_list_enable=YES 	 |                               Use a list of local users that will be placed in their home directory?

## Anonymous Access

- Here are some options that describe what an anomymous user can do :

|Setting|Description|
|------------|----|
anonymous_enable=YES 	      |      Allowing anonymous login
anon_upload_enable=YES 	       |     Allowing anonymous to upload files
anon_mkdir_write_enable=YES 	|    Allowing anonymous to create new directories
no_anon_password=YES 	  |          Do not ask anonymous for password
anon_root=/home/username/ftp |	    Directory for anonymous.
write_enable=YES 	         |       Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE


- /etc/ftpusers: used to deny access to system users .contains new line separated usernames.


## ftp Command Line


- commands

|Command| Description|
|-------------|------------|
status       |    get an overview of the server's settings
ls          |     list the contents of curent directory
debug         |   show debug information
trace         |   packet tracing on
get {file}       |download a file
put {file}      | upload a file
exit             |leave the session
        

### Get all available files

`$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136`

## ssl wraped FTP
        
`$ openssl s_client -connect x.x.x.x:21 -starttls ftp`
        
