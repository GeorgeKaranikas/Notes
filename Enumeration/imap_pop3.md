- imap port 143(tls port 993)
- pop3 110(tls 995)

Internet Message Access Protocol (IMAP) is client-server-based and allows synchronization of a local 
email client with the mailbox on the server, providing a kind of network file system for emails, 
allowing problem-free synchronization across several independent clients. POP3, on the other hand, 
does not have the same functionality as IMAP, and it only provides listing, retrieving, and deleting 
emails as functions at the email server. Therefore, protocols such as IMAP must be used for 
additional functionalities such as hierarchical mailboxes directly at the mail server, access to 
multiple mailboxes during a session, and preselection of emails.


The client establishes the connection to the server via port 143. For communication, it uses text-based commands in ASCII format. Several commands can be sent in succession without waiting for confirmation from the server.  Immediately after the connection is established, the user is authenticated by user name and password to the server. Access to the desired mailbox is only possible after successful authentication.

SMTP is usually used to send emails. By copying sent emails into an IMAP folder, all clients have access to all sent mails, regardless of the computer from which they were sent. Another advantage of the Internet Message Access Protocol is creating personal folders and folder structures in the mailbox. This feature makes the mailbox clearer and easier to manage. However, the storage space requirement on the email server increases.


# IMAP Commands

|Command 	             |       Description|
|----------------------|--------------------|
1 LOGIN                       |  username password 	User's login.
1 LIST "" * 	              |  Lists all directories.
1 CREATE "INBOX" 	           | Creates a mailbox with a specified name.
1 DELETE "INBOX" 	          |  Deletes a mailbox.
1 RENAME "ToRead" "Important" 	|Renames a mailbox.
1 LSUB "" * 	              |  Returns a subset of names from the set of names that the User has declared as being active or subscribed.
1 SELECT INBOX 	             |   Selects a mailbox so that messages in the mailbox can be accessed.
1 UNSELECT INBOX 	         |   Exits the selected mailbox.
1 FETCH <ID> all 	          |  Retrieves data associated with a message in the mailbox.
1 CLOSE 	                 |   Removes all messages with the Deleted flag set.
1 LOGOUT 	                  |  Closes the connection with the IMAP server.



# POP3 Commands

|Command 	        |            Description|
|-------------------|----------------------|
USER   username 	        |    Identifies the user.
PASS   password 	     |       Authentication of the user using its password.
STAT 	                 |       Requests the number of saved emails from the server.
LIST 	                |        Requests from the server the number and size of all emails.
RETR id 	            |        Requests the server to deliver the requested email by ID.
DELE id 	           |         Requests the server to delete the requested email by ID.
CAPA 	               |         Requests the server to display the server capabilities.
RSET 	              |          Requests the server to reset the transmitted information.
QUIT 	             |           Closes the connection with the POP3 server.


# Dangerous Settings


|Setting 	         |   Description|
|------------------|----------------|
auth_debug 	             |   Enables all authentication debug logging.
auth_debug_passwords 	|    This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.
auth_verbose 	     |       Logs unsuccessful authentication attempts and their reasons.
auth_verbose_passwords 	 |   Passwords used for authentication are logged and can also be truncated.
auth_anonymous_username |	This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism.


# Footprinting the Service

`$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC`

- By the commonName and organization name we might be able to check if the corporation is using a public email provider or their own

# Interact with creds
    
`$curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd -v`


# SSL Connection

- To interact with the IMAP or POP3 server over SSL, we can use openssl, as well as ncat

`$ openssl s_client -connect x.x.x.x:pop3s`

`$ openssl s_client -connect x.x.x.x:imaps`








