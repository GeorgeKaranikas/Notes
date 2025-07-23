

        osTicket is an open-source support ticketing system. It can be compared to systems such as Jira, OTRS, Request Tracker, and Spiceworks. osTicket can integrate user inquiries from email, phone, and web-based forms into a web interface. osTicket is written in PHP and uses a MySQL backend. It can be installed on Windows or Linux




                --Footprinting/Discovery/Enumeration
        

        Looking back at our EyeWitness scan from earlier, we notice a screenshot of an osTicket instance which also shows that a cookie named OSTSESSID was set when visiting the page.

        Also, most osTicket installs will showcase the osTicket logo with the phrase powered by in front of it in the page's footer. The footer may also contain the words Support Ticket System.


        osTicket is a web application that is highly maintained and serviced. If we look at the CVEs found over decades, we will not find many vulnerabilities and exploits that osTicket could have. This is an excellent example to show how important it is to understand how a web application works. Even if the application is not vulnerable, it can still be used for our purposes. Here we can break down the main functions into the layers:
                
                
                1. User input 	2. Processing 	3. Solution


        

                --Attacking osTicket
        
        A search for osTicket on exploit-db shows various issues, including remote file inclusion, SQL injection, arbitrary file upload, XSS, etc. osTicket version 1.14.1 suffers from CVE-2020-24881 which was an SSRF vulnerability. If exploited, this type of flaw may be leveraged to gain access to internal resources or perform internal port scanning.


        Aside from web application-related vulnerabilities, support portals can sometimes be used to obtain an email address for a company domain, which can be used to sign up for other exposed applications requiring an email verification to be sent.

        Suppose we find an exposed service such as a company's Slack server or GitLab, which requires a valid company email address to join. Many companies have a support email such as support@inlanefreight.local, and emails sent to this are available in online support portals that may range from Zendesk to an internal custom tool. Furthermore, a support portal may assign a temporary internal email address to a new ticket so users can quickly check its status.

        If we come across a customer support portal during our assessment and can submit a new ticket, we may be able to obtain a valid company email address.

        Now, if we log in, we can see information about the ticket and ways to post a reply. If the company set up their helpdesk software to correlate ticket numbers with emails, then any email sent to the email we received when registering, 940288@inlanefreight.local, would show up here. With this setup, if we can find an external portal such as a Wiki, chat service (Slack, Mattermost, Rocket.chat), or a Git repository such as GitLab or Bitbucket, we may be able to use this email to register an account and the help desk support portal to receive a sign-up confirmation email.



                --osTicket - Sensitive Data Exposure

        
        Let's say we are on an external penetration test. During our OSINT and information gathering, we discover several user credentials using the tool Dehashed (for our purposes, the sample data below is fictional).

        $ sudo python3 dehashed.py -q inlanefreight.local -p

        This dump shows cleartext passwords for two different users: jclayton and kgrimes. At this point, we have also performed subdomain enumeration and come across several interesting ones.

        We browse to each subdomain and find that many are defunct, but some are active and very promising


         Support.inlanefreight.local is hosting an osTicket instance, and vpn.inlanefreight.local is a Barracuda SSL VPN web portal that does not appear to be using multi-factor authentication.

        