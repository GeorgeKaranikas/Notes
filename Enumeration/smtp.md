- TCP port 25,587


The Simple Mail Transfer Protocol (SMTP) is a protocol for sending emails in an IP network. It can be used between an email client and an outgoing mail server or between two SMTP servers. SMTP is often combined with the IMAP or POP3 protocols, which can fetch emails and send emails. In principle, it is a client-server-based protocol, although SMTP can be used between a client and a server and between two SMTP servers. In this case, a server effectively acts as a client.

SMTP works unencrypted without further measures and transmits all commands, data, or authentication information in plain text. To prevent unauthorized reading of data, the SMTP is used in conjunction with SSL/TLS encryption. Under certain circumstances, a server uses a port other than the standard TCP port 25 for the encrypted connection, for example, TCP port 465.

    
    Client (MUA) 	➞ 	Submission Agent (MSA) 	➞ 	Open Relay (MTA) 	➞ 	Mail Delivery Agent (MDA) 	➞ 	Mailbox (POP3/IMAP)


- Mail User Agent (MUA)
- Mail Transfer Agent (MTA)
- Mail Submission Agent (MSA)
- Mail delivery agent (MDA)
    

# smtp commands

        
|Command 	 |           Description|
|------------|------------------|
AUTH PLAIN 	|    AUTH is a service extension used to authenticate the client.
HELO 	        |The client logs in with its computer name and thus starts the session.
MAIL FROM 	 |   The client names the email sender.
RCPT TO 	  |  The client names the email recipient.
DATA 	    |   The client initiates the transmission of the email.
RSET 	     |  The client aborts the initiated transmission but keeps the connection between client and server.
VRFY 	      |The client checks if a mailbox is available for message transfer.
EXPN 	      |The client also checks if a mailbox is available for messaging with this command.
NOOP 	      |The client requests a response from the server to prevent disconnection due to time-out.
QUIT 	      |The client terminates the session.



To interact with the SMTP server, we can use the telnet tool to initialize a TCP connection with the SMTP server. The actual initialization of the session is done with the command mentioned above, HELO or EHLO.

The command VRFY can be used to enumerate existing users on the system. However, this does not always work. Depending on how the SMTP server is configured, the SMTP server may issue code 252 and confirm the existence of a user that does not exist on the system. \


# Test for open relay

    
`$ sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v`


