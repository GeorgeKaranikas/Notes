

        \\\\Creating an AD Snapshot with Active Directory Explorer


    AD Explorer is part of the Sysinternal Suite and is described as:

    "An advanced Active Directory (AD) viewer and editor. You can use AD Explorer to navigate an AD database easily, define favorite locations, view object properties, and attributes without opening dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute."


    AD Explorer can also be used to save snapshots of an AD database for offline viewing and comparison. We can take a snapshot of AD at a point in time and explore it later, during the reporting phase, as you would explore any other database. It can also be used to perform a before and after comparison of AD to uncover changes in objects, attributes, and security permissions.


    \\Browsing AD with AD Explorer

    To take a snapshot of AD, go to File --> Create Snapshot and enter a name for the snapshot. Once it is complete, we can move it offline for further analysis.



        \\\PingCastle


    PingCastle is a powerful tool that evaluates the security posture of an AD environment and provides us the results in several different maps and graphs. Thinking about security for a second, if you do not have an active inventory of the hosts in your enterprise, PingCastle can be a great resource to help you gather one in a nice user-readable map of the domain. PingCastle is different from tools such as PowerView and BloodHound because, aside from providing us with enumeration data that can inform our attacks, it also provides a detailed report of the target domain's security level using a methodology based on a risk assessment/maturity framework. The scoring shown in the report is based on the Capability Maturity Model Integration (CMMI). For a quick look at the help context provided, you can issue the --help switch in cmd-prompt.


    \\Viewing the PingCastle Help Menu


    C:\htb> PingCastle.exe --help

    To run PingCastle, we can call the executable by typing PingCastle.exe into our CMD or PowerShell window or by clicking on the executable, and it will drop us into interactive mode, presenting us with a menu of options inside the Terminal User Interface (TUI).




            \\Group3r

    Group3r is a tool purpose-built to find vulnerabilities in Active Directory associated Group Policy. Group3r must be run from a domain-joined host with a domain user (it does not need to be an administrator), or in the context of a domain user (i.e., using runas /netonly).


    C:\htb> group3r.exe -f <filepath-name.log> 

    When running Group3r, we must specify the -s or the -f flag. These will specify whether to send results to stdout (-s), or to the file we want to send the results to (-f). For more options and usage information, utilize the -h flag, or check out the usage info at the link above.



            \\ADRecon

     In an assessment where stealth is not required, it is also worth running a tool like ADRecon and analyzing the results, just in case all of our enumeration missed something minor that may be useful to us or worth pointing out to our client.

     PS C:\htb> .\ADRecon.ps1

     Once done, ADRecon will drop a report for us in a new folder under the directory we executed from. We can see an example of the results in the terminal below. You will get a report in HTML format and a folder with CSV results. When generating the report, it should be noted that the program Excel needs to be installed, or the script will not automatically generate the report in that manner; it will just leave you with the .csv files. If you want output for Group Policy, you need to ensure the host you run from has the GroupPolicy PowerShell module installed. We can go back later and generate the Excel report from another host using the -GenExcel switch and feeding in the report folder.

     