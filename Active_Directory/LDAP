

        LDAP (Lightweight Directory Access Protocol) is a protocol used to access and manage directory information. A directory is a hierarchical data store that contains information about network resources such as users, groups, computers, printers, and other devices. 

        LDAP is commonly used for providing a central location for accessing and managing directory services. Directory services are collections of information about the organisation, its users, and assets–like usernames and passwords. 

        There are two popular implementations of LDAP: OpenLDAP, an open-source software widely used and supported, and Microsoft Active Directory, a Windows-based implementation that seamlessly integrates with other Microsoft products and services.

        Although LDAP and AD are related, they serve different purposes. LDAP is a protocol that specifies the method of accessing and modifying directory services, whereas AD is a directory service that stores and manages user and computer data. While LDAP can communicate with AD and other directory services, it is not a directory service itself. AD offers extra functionalities such as policy administration, single sign-on, and integration with various Microsoft products.



        LDAP works by using a client-server architecture. A client sends an LDAP request to a server, which searches the directory service and returns a response to the client. LDAP is a protocol that is simpler and more efficient than X.500, on which it is based. It uses a client-server model, where clients send requests to servers using LDAP messages encoded in ASN.1 (Abstract Syntax Notation One) and transmitted over TCP/IP (Transmission Control Protocol/Internet Protocol). The servers process the requests and send back responses using the same format. LDAP supports various requests, such as bind, unbind, search, compare, add, delete, modify, etc.

        LDAP requests are messages that clients send to servers to perform operations on data stored in a directory service. An LDAP request is comprised of several components:

        Session connection: The client connects to the server via an LDAP port (usually 389 or 636).
        
        Request type: The client specifies the operation it wants to perform, such as bind, search, etc.
        
        Request parameters: The client provides additional information for the request, such as the distinguished name (DN) of the entry to be accessed or modified, the scope and filter of the search query, the attributes and values to be added or changed, etc.
        
        Request ID: The client assigns a unique identifier for each request to match it with the corresponding response from the server.



        Once the server receives the request, it processes it and sends back a response message that includes several components:

        Response type: The server indicates the operation that was performed in response to the request.
        
        Result code: The server indicates whether or not the operation was successful and why.
        
        Matched DN: If applicable, the server returns the DN of the closest existing entry that matches the request.
        
        Referral: The server returns a URL of another server that may have more information about the request, if applicable.
        
        Response data: The server returns any additional data related to the response, such as the attributes and values of an entry that was searched or modified.

        After receiving and processing the response, the client disconnects from the LDAP port.




        --ldapsearch


        ldapsearch is a command-line utility used to search for information stored in a directory using the LDAP protocol. It is commonly used to query and retrieve data from an LDAP directory service.

        $ ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"




        Connect to the server ldap.example.com on port 389.
        
        Bind (authenticate) as cn=admin,dc=example,dc=com with password secret123.
        
        Search under the base DN ou=people,dc=example,dc=com.
        
        Use the filter (mail=john.doe@example.com) to find entries that have this email address.



             

        The server would process the request and send back a response, which might look something like this:


            dn: uid=jdoe,ou=people,dc=example,dc=com
            objectClass: inetOrgPerson
            objectClass: organizationalPerson
            objectClass: person
            objectClass: top
            cn: John Doe
            sn: Doe
            uid: jdoe
            mail: john.doe@example.com

            result: 0 Success


        
        
        --LDAP Injection



        LDAP injection is an attack that exploits web applications that use LDAP (Lightweight Directory Access Protocol) for authentication or storing user information. The attacker can inject malicious code or characters into LDAP queries to alter the application's behaviour, bypass security measures, and access sensitive data stored in the LDAP directory.


        To test for LDAP injection, you can use input values that contain special characters or operators that can change the query's meaning:


        Input 	                Description
        * 	            An asterisk * can match any number of characters.
        
        ( ) 	        Parentheses ( ) can group expressions.
        
        | 	            A vertical bar | can perform logical OR.
        
        & 	            An ampersand & can perform logical AND.
        
        (cn=*) 	        Input values that try to bypass authentication or authorisation checks by 
        injecting conditions that always evaluate to true can be used. For example, (cn=*) or (objectClass=*) can be used as input values for a username or password fields.


        For example, suppose an application uses the following LDAP query to authenticate users:


        (&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))


        Alternatively, if an attacker injects the * character into the $password field, the LDAP query would match any user account with any password that contains the injected string. This would allow the attacker to gain access to the application with any username, as shown below:
        
        
        $username = "dummy";
        $password = "*";
        (&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))



        -Enumeration

        As OpenLDAP runs on the server, it is safe to assume that the web application running on port 80 uses LDAP for authentication.

        Attempting to log in using a wildcard character (*) in the username and password fields grants access to the system, effectively bypassing any authentication measures that had been implemented. This is a significant security issue as it allows anyone with knowledge of the vulnerability to gain unauthorised access to the system and potentially sensitive data.


        




