

PRTG Network Monitor is agentless network monitor software. It can be used to monitor bandwidth usage, uptime and collect statistics from various hosts, including routers, switches, servers, and more. 

It works with an autodiscovery mode to scan areas of a network and create a device list. Once this list is created, it can gather further information from the detected devices using protocols such as ICMP, SNMP, WMI, NetFlow, and more. Devices can also communicate with the tool via a REST API. The software runs entirely from an AJAX-based website, but there is a desktop application available for Windows, Linux, and macOS. 



# Discovery/Footprinting/Enumeration

It can typically be found on common web ports such as 80, 443, or 8080. 


`$ curl -s http://10.129.201.50:8080/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version`



# Leveraging Known Vulnerabilities
    
[CVE-2018-9276](https://www.codewatch.org/blog/?p=453)


When creating a new notification, the Parameter field is passed directly into a PowerShell script without any type of input sanitization.

- Go to Setup ->Account Settings->Notifications and click on Add new notification.

- Give the notification a name and scroll down and tick the box next to EXECUTE PROGRAM

- Under Program File, select Demo exe notification - outfile.ps1 from the drop-down

- in the parameter field, enter a command (test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add)

- Finally, click the Save button.


-    After clicking Save, we will be redirected to the Notifications page and see our new notification named pwn in the list.

- After clicking Test we will get a pop-up that says EXE notification is queued up. If we receive any sort of error message here, we can go back and double-check the notification settings.

`$ sudo crackmapexec smb 10.129.201.50 -u prtgadm1 -p Pwn3d_by_PRTG! `


    